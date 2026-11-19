//! Installs Artitux's own handler in Wine's KUSER dispatcher slot and
//! classifies every call that arrives through it.
//!
//! Reflex calls require a copied stub discovered through its IAT and caller
//! evidence. A positively registered ART process instead recognizes Wine's
//! CALL-through-KUSER stubs directly. Both replay the evidenced raw SYSCALL;
//! marked ART bypasses instead retain Wine's original dispatcher and receive
//! the source contract's service/XMM normalization. Protocol semantics are
//! handled afterward at the [`super::sigsys_router`] boundary.
//!
//! See [`should_replay_raw`] for the classification rule.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::mem::trampoline_destination;
use crate::procmem::{read_memory, read_u32, read_u64, read_u64s};

const WINE_DISPATCHER_SLOT: u64 = 0x7ffe_1000;
const THUNK_RETURN_OFFSET: u64 = 0x1f;
const IAT_CAPACITY: usize = 4096;
const RAW_TARGET_TAG: u64 = 1 << 63;

// Exact saved frame constructed by dispatcher_bridge before changing stacks.
#[cfg(feature = "artifact")]
#[repr(C)]
struct DispatcherFrame {
    registers: [u64; 15], // R15..RAX, as pushed by the bridge.
    flags: u64,
    xmm: [[u64; 2]; 16],
    target: u64,
    return_address: u64,
}

#[cfg(feature = "artifact")]
const _: () = assert!(
    core::mem::offset_of!(DispatcherFrame, flags) == 0x78
        && core::mem::offset_of!(DispatcherFrame, xmm) == 0x80
        && core::mem::offset_of!(DispatcherFrame, target) == 0x180
        && core::mem::offset_of!(DispatcherFrame, return_address) == 0x188
        && core::mem::size_of::<DispatcherFrame>() == 0x190
);
const SYSCALL_INSTRUCTION: [u8; 2] = [0x0f, 0x05];
const PEB_IMAGE_BASE_OFFSET: u64 = 0x10;
const TEB_PEB_OFFSET: u64 = 0x60;
const IAT_SCAN_MAX_RETRY_INTERVAL: u64 = 1024;
/// Thunks read per `process_vm_readv` call while scanning an IAT/lookup
/// table, instead of one syscall per 8-byte entry — an import table with a
/// few hundred entries previously cost hundreds of syscalls per scan attempt.
const IAT_THUNK_CHUNK: usize = 64;
/// Open-addressed set of stub addresses; twice [`IAT_CAPACITY`] keeps probes
/// short, and a power of two keeps the index a mask.
const IAT_STUB_SLOTS: usize = IAT_CAPACITY * 2;

static ORIGINAL_DISPATCHER: AtomicU64 = AtomicU64::new(0);
static BRIDGE_INSTALLED: AtomicBool = AtomicBool::new(false);
static BRIDGE_INSTALL_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static BRIDGE_INSTALL_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static REFLEX_IMAGE_START: AtomicU64 = AtomicU64::new(0);
static REFLEX_IMAGE_END: AtomicU64 = AtomicU64::new(0);
static IAT_STUB_COUNT: AtomicU64 = AtomicU64::new(0);
static IAT_SCAN_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static IAT_SCAN_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static IAT_SCAN_MISS_LOGGED: AtomicBool = AtomicBool::new(false);
static IAT_SCAN_LOCK: AtomicBool = AtomicBool::new(false);
static IAT_STUBS: [AtomicU64; IAT_STUB_SLOTS] = [const { AtomicU64::new(0) }; IAT_STUB_SLOTS];

unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
    fn debug_log_dec(prefix: *const core::ffi::c_char, value: u64);
}

fn log(message: &'static core::ffi::CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn log_hex(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_hex(prefix.as_ptr(), value) };
}

fn log_dec(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_dec(prefix.as_ptr(), value) };
}

fn log_install_failure() {
    if !BRIDGE_INSTALL_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"reflex bridge install failed; will retry at KUSER handshake");
    }
}

#[cfg(feature = "cpuid")]
pub(super) fn register_reflex_dispatch_handler(handler: u64) {
    register_reflex_image(handler);
}

/// Locate the loaded PE image containing `handler` (Reflex's registered
/// resume/dispatch target) by walking backward from its page in
/// `0x1000`-sized steps looking for a `MZ`/`PE` header whose `SizeOfImage`
/// covers it. Reflex's own image range, once known, lets
/// [`should_replay_raw`]'s caller-evidence check exclude Reflex's *internal*
/// calls (which are never syscall stubs) from the replay path.
#[cfg(feature = "cpuid")]
fn register_reflex_image(handler: u64) {
    if handler == 0 || REFLEX_IMAGE_START.load(Ordering::Acquire) != 0 {
        return;
    }
    let first_page = handler & !0xfff;
    for offset in (0..=0x10_0000).step_by(0x1000) {
        let Some(base) = first_page.checked_sub(offset) else {
            break;
        };
        let mut dos = [0u8; 0x40];
        if !read_memory(base, &mut dos) || dos[..2] != *b"MZ" {
            continue;
        }
        let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
        if pe_offset > 0x1000 {
            continue;
        }
        let mut headers = [0u8; 0x60];
        if !read_memory(base + pe_offset, &mut headers) || headers[..4] != *b"PE\0\0" {
            continue;
        }
        let image_size = u32::from_le_bytes(headers[80..84].try_into().unwrap()) as u64;
        let Some(end) = base.checked_add(image_size) else {
            continue;
        };
        if image_size != 0 && (base..end).contains(&handler) {
            REFLEX_IMAGE_END.store(end, Ordering::Relaxed);
            REFLEX_IMAGE_START.store(base, Ordering::Release);
            return;
        }
    }
}

fn is_reflex_address(address: u64) -> bool {
    let start = REFLEX_IMAGE_START.load(Ordering::Acquire);
    let end = REFLEX_IMAGE_END.load(Ordering::Acquire);
    start != 0 && (start..end).contains(&address)
}

fn stub_probe(address: u64) -> impl Iterator<Item = usize> {
    let hash = (address >> 4).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32;
    (0..IAT_STUB_SLOTS).map(move |offset| (hash as usize + offset) & (IAT_STUB_SLOTS - 1))
}

/// Inserts are serialized by `IAT_SCAN_LOCK`; slots only ever go from zero to
/// an address, so lock-free readers see a consistent set.
fn remember_stub(address: u64) -> bool {
    if address == 0 || IAT_STUB_COUNT.load(Ordering::Acquire) >= IAT_CAPACITY as u64 {
        return false;
    }
    for index in stub_probe(address) {
        match IAT_STUBS[index].compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                IAT_STUB_COUNT.fetch_add(1, Ordering::AcqRel);
                return true;
            }
            Err(existing) if existing == address => return false,
            Err(_) => {}
        }
    }
    false
}

/// Scan the current process's mapped main-image IAT for Reflex-style
/// trampolines. This uses PE import descriptors to bound the scan, so syscall
/// routing does not depend on observing Reflex's individual protection calls.
/// The scan is retried until Reflex has populated the IAT.
fn scan_main_image_iat() -> usize {
    if IAT_SCAN_LOCK
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return 0;
    }
    let found = scan_main_image_iat_locked();
    IAT_SCAN_LOCK.store(false, Ordering::Release);
    if found == 0 && !IAT_SCAN_MISS_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"main PE IAT scan found no Reflex trampolines yet");
    }
    found
}

fn scan_main_image_iat_locked() -> usize {
    let mut gs_base = 0u64;
    // Wine's x86-64 TEB is the thread GS base; TEB+0x60 points to the PEB.
    // Use arch_prctl rather than reading a compiler/platform-specific GS
    // intrinsic from this shared library.
    let got_gs = unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            0x1004i64, // ARCH_GET_GS
            &mut gs_base as *mut u64,
        )
    } == 0;
    if !got_gs || gs_base == 0 {
        return 0;
    }
    let Some(peb) = read_u64(gs_base.saturating_add(TEB_PEB_OFFSET)) else {
        return 0;
    };
    let Some(image_base) = read_u64(peb.saturating_add(PEB_IMAGE_BASE_OFFSET)) else {
        return 0;
    };
    if image_base == 0 {
        return 0;
    }

    let Some(mz) = read_u32(image_base) else {
        return 0;
    };
    if mz as u16 != 0x5a4d {
        return 0;
    }
    let Some(pe_offset) = read_u32(image_base.saturating_add(0x3c)) else {
        return 0;
    };
    if pe_offset > 0x1000 {
        return 0;
    }
    let Some(pe_signature) = read_u32(image_base.saturating_add(pe_offset as u64)) else {
        return 0;
    };
    if pe_signature != u32::from_le_bytes(*b"PE\0\0") {
        return 0;
    }

    let optional = image_base
        .saturating_add(pe_offset as u64)
        .saturating_add(24);
    let Some(magic) = read_u32(optional) else {
        return 0;
    };
    if magic as u16 != 0x20b {
        return 0;
    }
    let Some(image_size) = read_u32(optional.saturating_add(56)) else {
        return 0;
    };
    let Some(import_rva) = read_u32(optional.saturating_add(120)) else {
        return 0;
    };
    if image_size == 0 || import_rva == 0 || import_rva >= image_size {
        return 0;
    }

    let mut found = 0usize;
    let max_descriptors = ((image_size - import_rva) / 20).min(4096);
    for index in 0..max_descriptors {
        let descriptor = image_base
            .saturating_add(import_rva as u64)
            .saturating_add(u64::from(index) * 20);
        let Some(name_rva) = read_u32(descriptor.saturating_add(12)) else {
            break;
        };
        if name_rva == 0 {
            break;
        }
        let Some(iat_rva) = read_u32(descriptor.saturating_add(16)) else {
            break;
        };
        let Some(original_thunk_rva) = read_u32(descriptor) else {
            break;
        };
        if iat_rva == 0 || iat_rva >= image_size {
            continue;
        }

        // Count imports through the original lookup table, as Reflex does.
        // This avoids scanning gaps between unrelated IAT runs in a merged
        // range; if OriginalFirstThunk is absent, the IAT retains its zero
        // terminator after Reflex replaces its non-null entries.
        let lookup_rva = if original_thunk_rva == 0 {
            iat_rva
        } else {
            original_thunk_rva
        };
        if lookup_rva >= image_size {
            continue;
        }
        let max_thunks = (image_size.saturating_sub(lookup_rva) / 8).min(65_536);
        // Read the lookup table and IAT a chunk at a time; stopping at the
        // first unreadable or zero entry matches reading them one by one.
        let mut thunk = 0u32;
        'thunks: while thunk < max_thunks {
            let count = ((max_thunks - thunk) as usize).min(IAT_THUNK_CHUNK);
            let offset = u64::from(thunk) * 8;
            let mut imports = [0u64; IAT_THUNK_CHUNK];
            let mut values = [0u64; IAT_THUNK_CHUNK];
            let imports_read = read_u64s(
                image_base
                    .saturating_add(lookup_rva as u64)
                    .saturating_add(offset),
                &mut imports,
                count,
            );
            let values_read = read_u64s(
                image_base
                    .saturating_add(iat_rva as u64)
                    .saturating_add(offset),
                &mut values,
                count,
            );
            for index in 0..count {
                if index >= imports_read
                    || imports[index] == 0
                    || index >= values_read
                    || values[index] == 0
                {
                    break 'thunks;
                }
                if let Some(destination) = trampoline_destination(values[index])
                    && remember_stub(destination)
                {
                    found += 1;
                }
            }
            thunk += count as u32;
        }
    }
    if found != 0 && !IAT_SCAN_SUCCESS_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"reflex IAT trampolines discovered from main PE import table");
        log_hex(c"reflex main image base=", image_base);
        log_dec(
            c"reflex IAT trampoline targets discovered=",
            IAT_STUB_COUNT.load(Ordering::Acquire),
        );
    }
    found
}

pub(super) fn maybe_scan_main_image_iat() {
    if IAT_STUB_COUNT.load(Ordering::Acquire) != 0
        || REFLEX_IMAGE_START.load(Ordering::Acquire) == 0
    {
        return;
    }
    let attempt = IAT_SCAN_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    if should_retry_iat_scan(attempt) {
        let _ = scan_main_image_iat();
    }
}

fn should_retry_iat_scan(attempt: u64) -> bool {
    // Retry promptly during registration, then bound the cost for games
    // whose IAT never contains a Reflex trampoline. Late hooks are still
    // discovered on a later call, at most 1024 dispatcher hits away.
    attempt == 0 || attempt.is_power_of_two() || attempt.is_multiple_of(IAT_SCAN_MAX_RETRY_INTERVAL)
}

fn matches_iat_stub(return_address: u64) -> bool {
    if IAT_STUB_COUNT.load(Ordering::Acquire) == 0 {
        return false;
    }
    let Some(stub) = stub_for_return(return_address) else {
        return false;
    };
    for index in stub_probe(stub) {
        match IAT_STUBS[index].load(Ordering::Acquire) {
            0 => return false,
            entry if entry == stub => return true,
            _ => {}
        }
    }
    false
}

/// The stub entry whose call returns to `return_address`.
fn stub_for_return(return_address: u64) -> Option<u64> {
    return_address
        .checked_sub(THUNK_RETURN_OFFSET)
        .filter(|&stub| stub != 0)
}

#[cfg(test)]
fn return_matches_stub(return_address: u64, stub: u64) -> bool {
    stub_for_return(return_address) == Some(stub)
}

fn find_raw_syscall_instruction(code: &[u8], code_address: u64, service: u64) -> Option<u64> {
    for syscall_offset in (2..=code.len()).rev() {
        if code[syscall_offset - 2..syscall_offset] != SYSCALL_INSTRUCTION {
            continue;
        }
        if syscall_service_before(code, syscall_offset) == Some(service) {
            return code_address.checked_add((syscall_offset - 2) as u64);
        }
    }
    None
}

fn syscall_service_before(code: &[u8], syscall_offset: usize) -> Option<u64> {
    let start = syscall_offset.saturating_sub(26);
    (start..syscall_offset.saturating_sub(8))
        .rev()
        .find(|&offset| code[offset..offset + 3] == [0x4c, 0x8b, 0xd1] && code[offset + 3] == 0xb8)
        .map(|offset| u32::from_le_bytes(code[offset + 4..offset + 8].try_into().unwrap()) as u64)
}

fn find_syscall(return_address: u64, service: u64) -> Option<u64> {
    for window in [0x80usize, 0x40, 0x20] {
        let Some(start) = return_address.checked_sub(window as u64) else {
            continue;
        };
        let mut bytes = [0u8; 0x80];
        if !read_memory(start, &mut bytes[..window]) {
            continue;
        }
        if let Some(address) = find_raw_syscall_instruction(&bytes[..window], start, service) {
            return Some(address);
        }
    }
    None
}

/// Recognize Wine's CALL-through-KUSER thunk before bypassing the narrower
/// Reflex IAT/caller filters. The service, SystemCall branch, and CALL slot
/// must all belong to this same stub; an unrelated nearby SYSCALL is not
/// sufficient evidence.
fn find_artifact_wine_syscall(return_address: u64, service: u64) -> Option<u64> {
    let start = stub_for_return(return_address)?;
    let service = u32::try_from(service).ok()?;
    let mut code = [0u8; 32];
    if !read_memory(start, &mut code)
        || code[..4] != [0x4c, 0x8b, 0xd1, 0xb8]
        || code[4..8] != service.to_le_bytes()
        || code[8..0x15]
            != [
                0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3,
            ]
        || code[0x15..]
            != [
                0xeb, 0x01, 0xc3, 0xff, 0x14, 0x25, 0x00, 0x10, 0xfe, 0x7f, 0xc3,
            ]
    {
        return None;
    }
    start.checked_add(0x12)
}

/// The evidence `dispatcher_target` gathers for one KUSER dispatcher call,
/// in the order it becomes available (cheapest first, so the expensive
/// `find_syscall` memory scan is only attempted once the cheaper checks
/// already passed).
#[derive(Clone, Copy)]
struct DispatchEvidence {
    /// Wine's own dispatcher has been observed (the bridge is fully armed).
    original_dispatcher_known: bool,
    /// The return address matches a stub the IAT scan found Reflex hooking.
    stub_match: bool,
    /// The caller is inside Reflex's own image, not a copied stub calling in
    /// from outside it.
    caller_is_reflex_image: bool,
    /// A raw `syscall` instruction for this service was found near the
    /// return address.
    raw_syscall_found: bool,
}

/// Reflex requires the IAT/caller evidence. A registered ART callback instead
/// uses an independently recognized Wine CALL thunk; both paths require the
/// original dispatcher and a matching raw SYSCALL.
fn should_replay_raw(evidence: DispatchEvidence, artifact: bool) -> bool {
    evidence.original_dispatcher_known
        && evidence.raw_syscall_found
        && (artifact || (evidence.stub_match && !evidence.caller_is_reflex_image))
}

/// The KUSER dispatcher bridge's Rust selector, called from
/// [`dispatcher_bridge`]'s naked-asm trampoline on Wine's own stack. Returns
/// the target to jump to: either the original Wine dispatcher, or a raw
/// syscall address tagged in bit 63 (cleared and consumed by the trampoline
/// itself before it jumps there — see the frame-layout comment on
/// `dispatcher_bridge`).
unsafe extern "C" fn dispatcher_target(
    return_address: u64,
    service: u64,
    r10: u64,
    _saved_frame: *mut c_void,
    xmm5: u64,
    entry_rsp: u64,
) -> u64 {
    let _ = r10;
    let original = ORIGINAL_DISPATCHER.load(Ordering::Acquire);
    #[cfg(feature = "artifact")]
    let artifact = crate::artifact::active() && crate::artifact::syscall_target().is_some();
    #[cfg(not(feature = "artifact"))]
    let artifact = false;
    #[cfg(feature = "artifact")]
    {
        // SAFETY: dispatcher_bridge saved the complete, exclusively owned
        // frame before switching to the selector's private stack.
        let frame = unsafe { &mut *_saved_frame.cast::<DispatcherFrame>() };
        unsafe {
            dispatcher_target_for_frame(
                return_address,
                service,
                entry_rsp,
                original,
                artifact,
                xmm5,
                frame,
            )
        }
    }
    #[cfg(not(feature = "artifact"))]
    {
        let _ = xmm5;
        unsafe {
            dispatcher_target_for_process(return_address, service, entry_rsp, original, artifact)
        }
    }
}

unsafe fn dispatcher_target_for_process(
    return_address: u64,
    service: u64,
    entry_rsp: u64,
    original: u64,
    artifact: bool,
) -> u64 {
    #[cfg(feature = "artifact")]
    let _dispatch_guard = unsafe { crate::artifact::wine_dispatch_guard() };
    if !artifact {
        maybe_scan_main_image_iat();
        super::unixlib_repair::maybe_repair_wine_unixlib_exports();
    }
    let trap_rsp = entry_rsp.saturating_add(8);
    #[cfg(feature = "artifact")]
    if artifact {
        super::artifact_flags::retire(trap_rsp);
    }
    let mut tid = 0;
    if super::reflex_markers::has_active_markers() {
        tid = unsafe { libc::gettid() as u64 };
        super::reflex_markers::retire_markers(tid, trap_rsp);
    }

    if original == 0 {
        return original;
    }
    let stub_match = !artifact && matches_iat_stub(return_address);
    if !artifact && !stub_match {
        return original;
    }
    let caller_is_reflex_image =
        !artifact && is_reflex_address(read_u64(entry_rsp.saturating_add(8)).unwrap_or(0));
    if !artifact && caller_is_reflex_image {
        return original;
    }
    let raw = if artifact {
        find_artifact_wine_syscall(return_address, service)
    } else {
        find_syscall(return_address, service)
    };
    if !should_replay_raw(
        DispatchEvidence {
            original_dispatcher_known: true,
            stub_match,
            caller_is_reflex_image,
            raw_syscall_found: raw.is_some(),
        },
        artifact,
    ) {
        return original;
    }
    let raw = raw.expect("raw_syscall_found was checked above");
    let trap_rip = raw.saturating_add(2);
    #[cfg(feature = "artifact")]
    if artifact {
        // Keep ART's per-call flags independently of the Reflex marker
        // table, including when a later same-site call must be re-armed.
        if !super::artifact_flags::reserve(trap_rsp, trap_rip) {
            const MESSAGE: &[u8] = b"Artitux: ART syscall flag storage unavailable\n";
            unsafe {
                libc::write(libc::STDERR_FILENO, MESSAGE.as_ptr().cast(), MESSAGE.len());
                libc::_exit(127);
            }
        }
        return raw | RAW_TARGET_TAG;
    }
    if tid == 0 {
        tid = unsafe { libc::gettid() as u64 };
    }
    if !super::reflex_markers::remember_marker(tid, trap_rsp, trap_rip) {
        return original;
    }
    raw | RAW_TARGET_TAG
}

#[cfg(feature = "artifact")]
unsafe fn dispatcher_target_for_frame(
    return_address: u64,
    service: u64,
    entry_rsp: u64,
    original: u64,
    artifact: bool,
    xmm5: u64,
    frame: &mut DispatcherFrame,
) -> u64 {
    if artifact && original != 0 && crate::artifact::is_syscall_bypass(xmm5) {
        // The source contract applies before canonical-stub decoding: even
        // noncanonical callers carry a real service in EAX. Leave their
        // continuation, flags, arguments and nonvolatile state untouched.
        let service = u64::from(service as u32);
        frame.registers[14] = service;
        frame.xmm[4] = [service, 0];
        frame.xmm[5] = [0, 0];
        // An ordinary bypass never reserves/retires raw-replay flag frames,
        // changes the selector, or executes a Windows ID as a Linux syscall.
        return original;
    }
    unsafe { dispatcher_target_for_process(return_address, service, entry_rsp, original, artifact) }
}

/// Private stacks for the bridge's Rust selector, one slot per Windows thread
/// id (`TEB.ClientId.UniqueThread`, a multiple of four). The first word of a
/// slot is a spin lock, so two threads that share a slot only serialize. The
/// array lives in `.bss`, so only the pages a thread actually uses are ever
/// committed.
const BRIDGE_STACK_SLOTS: usize = 1024;
const BRIDGE_STACK_SHIFT: usize = 15;

#[repr(C, align(4096))]
struct BridgeStacks([u8; BRIDGE_STACK_SLOTS << BRIDGE_STACK_SHIFT]);

static mut BRIDGE_STACKS: BridgeStacks =
    BridgeStacks([0; BRIDGE_STACK_SLOTS << BRIDGE_STACK_SHIFT]);

/// Wine's KUSER dispatcher slot trampoline. Saves every register a Windows
/// syscall stub's caller could observe, runs [`dispatcher_target`] on a
/// private per-thread stack (see the field comment on `BRIDGE_STACKS`), and
/// restores everything before jumping to the chosen target, preserving ABI
/// parity on the direct-replay path.
#[cfg(feature = "kuser")]
#[unsafe(naked)]
unsafe extern "C" fn dispatcher_bridge() {
    core::arch::naked_asm!(
        "lea rsp, [rsp - 0x108]",
        "movdqu [rsp + 0x00], xmm0", "movdqu [rsp + 0x10], xmm1", "movdqu [rsp + 0x20], xmm2", "movdqu [rsp + 0x30], xmm3",
        "movdqu [rsp + 0x40], xmm4", "movdqu [rsp + 0x50], xmm5", "movdqu [rsp + 0x60], xmm6", "movdqu [rsp + 0x70], xmm7",
        "movdqu [rsp + 0x80], xmm8", "movdqu [rsp + 0x90], xmm9", "movdqu [rsp + 0xa0], xmm10", "movdqu [rsp + 0xb0], xmm11",
        "movdqu [rsp + 0xc0], xmm12", "movdqu [rsp + 0xd0], xmm13", "movdqu [rsp + 0xe0], xmm14", "movdqu [rsp + 0xf0], xmm15",
        "pushfq", "push rax", "push rbx", "push rcx", "push rdx", "push rsi", "push rdi", "push rbp", "push r8", "push r9", "push r10", "push r11", "push r12", "push r13", "push r14", "push r15",
        "mov rbx, rsp",
        "mov rdi, [rbx + 0x188]", "lea r9, [rbx + 0x188]", "mov rsi, [rbx + 0x70]", "mov rdx, [rbx + 0x28]", "mov rcx, rbx", "mov r8, [rbx + 0xd0]",
        // Run the Rust selector on a private per-thread stack. Everything
        // above this point is spilled to the Windows stack inside a fixed
        // 0x190-byte frame, like the Reflex handler itself; the selector's
        // much deeper call frames must not scribble further below the caller's
        // stack pointer, which Denuvo's VM reads back as scratch. A syscall
        // never touches user stack on Windows. All registers are already saved
        // in the frame, so RAX and R15 are free (R15 is callee-saved and holds
        // the stack slot across the call).
        "lea r15, [rip + {stacks}]",
        "mov rax, gs:[0x48]",
        "shr rax, 2",
        "and eax, {slot_mask}",
        "shl rax, {slot_shift}",
        "add r15, rax",
        "3:",
        "lock bts dword ptr [r15], 0",
        "jnc 4f",
        "pause",
        "jmp 3b",
        "4:",
        "lea rsp, [r15 + {slot_size}]",
        "call {target}",
        "mov dword ptr [r15], 0",
        "mov rsp, rbx", "mov [rsp + 0x180], rax",
        "mov r15, [rsp + 0x00]", "mov r14, [rsp + 0x08]", "mov r13, [rsp + 0x10]", "mov r12, [rsp + 0x18]", "mov r11, [rsp + 0x20]", "mov r10, [rsp + 0x28]", "mov r9, [rsp + 0x30]", "mov r8, [rsp + 0x38]", "mov rbp, [rsp + 0x40]", "mov rdi, [rsp + 0x48]", "mov rsi, [rsp + 0x50]", "mov rdx, [rsp + 0x58]", "mov rcx, [rsp + 0x60]", "mov rbx, [rsp + 0x68]", "mov rax, [rsp + 0x70]",
        "push qword ptr [rsp + 0x78]", "popfq",
        "movdqu xmm0, [rsp + 0x80]", "movdqu xmm1, [rsp + 0x90]", "movdqu xmm2, [rsp + 0xa0]", "movdqu xmm3, [rsp + 0xb0]", "movdqu xmm4, [rsp + 0xc0]", "movdqu xmm5, [rsp + 0xd0]", "movdqu xmm6, [rsp + 0xe0]", "movdqu xmm7, [rsp + 0xf0]", "movdqu xmm8, [rsp + 0x100]", "movdqu xmm9, [rsp + 0x110]", "movdqu xmm10, [rsp + 0x120]", "movdqu xmm11, [rsp + 0x130]", "movdqu xmm12, [rsp + 0x140]", "movdqu xmm13, [rsp + 0x150]", "movdqu xmm14, [rsp + 0x160]", "movdqu xmm15, [rsp + 0x170]",
        // The two exits below land rsp one word apart (0x190 vs. 0x188) on
        // purpose, to account for the KUSER call's extra stack word.
        // `[rsp+0x188]` here is
        // `entry_rsp`: the value RSP held at the moment this trampoline was
        // entered, which is where the ntdll stub's own `call
        // [dispatcher_slot]` pushed its return address (call it
        // RET_ADDR — the address of the stub's own trailing `ret`).
        // `[entry_rsp+8]` is one call frame further out: whatever the stub
        // itself would eventually return to, once *its* `ret` runs.
        //
        // Ordinary path (2:, target = Wine's real dispatcher): this is a
        // tail call, so RSP must be exactly `entry_rsp` with RET_ADDR still
        // at `[rsp]` — Wine's dispatcher runs as a normal called function,
        // eventually does its own `ret`, consumes RET_ADDR, and lands back
        // on the stub's trailing `ret`, which then consumes `[entry_rsp+8]`
        // and returns to the stub's real caller. Two `ret`s total, matching
        // a real `call [dispatcher]; ret` sequence.
        //
        // Tagged path (target = a raw `syscall` instruction found by
        // `find_syscall`, tag bit cleared above): there is no dispatcher
        // call to unwind here — the whole point is to emulate the direct
        // route, where the stub's own inline `test;jne;syscall;ret` runs
        // with no KUSER dispatcher call in between at all. The instruction
        // right after any such `syscall` is always that same `ret` (it's
        // part of the fixed head+branch signature `pe_stub_layout.rs`
        // matches on, so this holds for Reflex's copied stub too). For that
        // one `ret` to consume `[entry_rsp+8]` directly — skipping RET_ADDR
        // entirely, since in the direct route it never existed — RSP must
        // already be `entry_rsp+8` before the jump. Hence `0x190`/`-0x10`
        // instead of `0x188`/`-8`: one extra word, for the one dispatcher
        // call this path never actually makes.
        "bt qword ptr [rsp + 0x180], 63", "jnc 2f", "btr qword ptr [rsp + 0x180], 63",
        "and qword ptr [rsp + 0x78], {clear_flags}", "or qword ptr [rsp + 0x78], {set_flags}", "push qword ptr [rsp + 0x78]", "popfq",
        "lea rsp, [rsp + 0x190]", "jmp qword ptr [rsp - 0x10]",
        "2:", "push qword ptr [rsp + 0x78]", "popfq", "lea rsp, [rsp + 0x188]", "jmp qword ptr [rsp - 8]",
        target = sym dispatcher_target,
        stacks = sym BRIDGE_STACKS,
        slot_mask = const BRIDGE_STACK_SLOTS - 1,
        slot_shift = const BRIDGE_STACK_SHIFT,
        slot_size = const 1usize << BRIDGE_STACK_SHIFT,
        clear_flags = const -0x882i32,
        set_flags = const 0x44u32,
    );
}

fn dispatcher_page_protection(page: u64, size: u64) -> Option<libc::c_int> {
    let end = page.checked_add(size)?;
    let mut protection = None;
    crate::maps::find_line(|line| {
        let Some(mapping) = crate::maps::parse(line) else {
            return false;
        };
        if mapping.start > page || mapping.end < end {
            return false;
        }
        let permissions = mapping.permissions;
        if permissions.len() != 4
            || permissions[0] != b'r'
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b'p' | b's')
        {
            return true;
        }
        let mut flags = libc::PROT_READ;
        if permissions[1] == b'w' {
            flags |= libc::PROT_WRITE;
        }
        if permissions[2] == b'x' {
            flags |= libc::PROT_EXEC;
        }
        protection = Some(flags);
        true
    });
    protection
}

/// The caller holds `PageGuard` and has prepared the ART page, if applicable.
unsafe fn swap_dispatcher_slot(
    slot: *mut u64,
    bridge: u64,
    original: &AtomicU64,
    expected_original: Option<u64>,
) -> bool {
    let address = slot as u64;
    let size = artitux::kuser::PAGE_SIZE as u64;
    let page = address & !(size - 1);
    let Some(page_end) = page.checked_add(size) else {
        return false;
    };
    if address == 0
        || !address.is_multiple_of(8)
        || address.checked_add(8).is_none_or(|end| end > page_end)
    {
        return false;
    }
    let Some(protection) = dispatcher_page_protection(page, size) else {
        return false;
    };
    let change_protection = protection & libc::PROT_WRITE == 0;
    if change_protection
        && unsafe {
            libc::mprotect(
                page as *mut c_void,
                size as usize,
                protection | libc::PROT_WRITE,
            )
        } != 0
    {
        return false;
    }
    let observed = unsafe { slot.read_volatile() };
    let installed = observed != 0
        && observed != bridge
        && expected_original.is_none_or(|expected| observed == expected);
    let previous_original = original.load(Ordering::Acquire);
    let already_installed = observed == bridge && previous_original != 0;
    if installed {
        original.store(observed, Ordering::Release);
        unsafe { slot.write_volatile(bridge) };
    }
    let restored = !change_protection
        || unsafe { libc::mprotect(page as *mut c_void, size as usize, protection) } == 0;
    if !restored {
        if installed {
            // The failed restore leaves the page writable. Do not leave a
            // bridge installed when its installation was reported as failed.
            unsafe { slot.write_volatile(observed) };
            original.store(previous_original, Ordering::Release);
        }
        return false;
    }
    installed || already_installed
}

/// Swap Wine's KUSER dispatcher slot for [`dispatcher_bridge`]. Idempotent;
/// safe to call repeatedly until Wine has populated the slot (see the retry
/// note in `kuser.rs::artitux_setup_kuser`).
pub(super) fn install() -> bool {
    #[cfg(feature = "artifact")]
    let verify_slot = crate::artifact::detected();
    #[cfg(not(feature = "artifact"))]
    let verify_slot = false;
    let slot = WINE_DISPATCHER_SLOT as *mut u64;
    let bridge = dispatcher_bridge as *const () as u64;
    if BRIDGE_INSTALLED.load(Ordering::Acquire) {
        if !verify_slot {
            return true;
        }
        if ORIGINAL_DISPATCHER.load(Ordering::Acquire) != 0
            && read_u64(WINE_DISPATCHER_SLOT) == Some(bridge)
        {
            return true;
        }
    }
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        log_install_failure();
        return false;
    };
    let cached = BRIDGE_INSTALLED.load(Ordering::Acquire);
    if cached && !verify_slot {
        return true;
    }
    let known_original = ORIGINAL_DISPATCHER.load(Ordering::Acquire);
    if cached && verify_slot {
        match read_u64(WINE_DISPATCHER_SLOT) {
            Some(value) if value == bridge && known_original != 0 => return true,
            Some(value) if value == known_original && known_original != 0 => {}
            _ => {
                log_install_failure();
                return false;
            }
        }
    }
    let expected_original = (verify_slot && known_original != 0).then_some(known_original);
    if unsafe { swap_dispatcher_slot(slot, bridge, &ORIGINAL_DISPATCHER, expected_original) } {
        BRIDGE_INSTALLED.store(true, Ordering::Release);
        if !BRIDGE_INSTALL_SUCCESS_LOGGED.swap(true, Ordering::AcqRel) {
            log(c"reflex bridge installed");
            log_hex(
                c"reflex bridge original Wine dispatcher=",
                ORIGINAL_DISPATCHER.load(Ordering::Acquire),
            );
        }
        true
    } else {
        log_install_failure();
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DispatchEvidence, find_raw_syscall_instruction, return_matches_stub, should_replay_raw,
        should_retry_iat_scan,
    };

    #[test]
    fn iat_scan_retries_taper_off_but_continue_for_late_hooks() {
        for attempt in [0, 1, 2, 4, 8, 16, 1024, 2048] {
            assert!(should_retry_iat_scan(attempt));
        }
        for attempt in [3, 6, 17, 1023, 1025, 2047] {
            assert!(!should_retry_iat_scan(attempt));
        }
    }

    #[test]
    fn copied_stub_lookup_requires_the_requested_service_number() {
        let code = [0x4c, 0x8b, 0xd1, 0xb8, 0x46, 0x02, 0x00, 0x00, 0x0f, 0x05];
        assert_eq!(
            find_raw_syscall_instruction(&code, 0x1234_5000, 0x246),
            Some(0x1234_5008)
        );
        assert_eq!(
            find_raw_syscall_instruction(&code, 0x1234_5000, 0x206),
            None
        );
    }

    #[test]
    fn dispatcher_return_must_match_the_discovered_stub_entry() {
        assert!(return_matches_stub(0x10001f, 0x100000));
        assert!(!return_matches_stub(0x100020, 0x100000));
        assert!(!return_matches_stub(0x10, 0x100000));
    }

    #[test]
    fn replays_raw_only_when_all_evidence_lines_up() {
        let all_true = DispatchEvidence {
            original_dispatcher_known: true,
            stub_match: true,
            caller_is_reflex_image: false,
            raw_syscall_found: true,
        };
        assert!(should_replay_raw(all_true, false));

        assert!(!should_replay_raw(
            DispatchEvidence {
                original_dispatcher_known: false,
                ..all_true
            },
            false
        ));
        assert!(!should_replay_raw(
            DispatchEvidence {
                stub_match: false,
                ..all_true
            },
            false
        ));
        assert!(!should_replay_raw(
            DispatchEvidence {
                caller_is_reflex_image: true,
                ..all_true
            },
            false
        ));
        assert!(!should_replay_raw(
            DispatchEvidence {
                raw_syscall_found: false,
                ..all_true
            },
            false
        ));
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn artifact_policy_does_not_apply_reflex_iat_or_caller_filters() {
        let evidence = DispatchEvidence {
            original_dispatcher_known: true,
            stub_match: false,
            caller_is_reflex_image: true,
            raw_syscall_found: true,
        };
        assert!(should_replay_raw(evidence, true));
        assert!(!should_replay_raw(evidence, false));
        assert!(!should_replay_raw(
            DispatchEvidence {
                original_dispatcher_known: false,
                ..evidence
            },
            true
        ));
        assert!(!should_replay_raw(
            DispatchEvidence {
                raw_syscall_found: false,
                ..evidence
            },
            true
        ));
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    struct WineCallStub {
        code: Box<[u8; 256]>,
        stack: Box<[u64; 2]>,
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    impl WineCallStub {
        const START: usize = 128;
        const SERVICE: u64 = 0x246;
        const ORIGINAL: u64 = 0x1122_3344_5566;

        fn new() -> Self {
            let mut code = Box::new([0x90; 256]);
            code[Self::START..Self::START + 32].copy_from_slice(&[
                0x4c, 0x8b, 0xd1, 0xb8, 0x46, 0x02, 0x00, 0x00, 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe,
                0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3, 0xeb, 0x01, 0xc3, 0xff, 0x14, 0x25, 0x00,
                0x10, 0xfe, 0x7f, 0xc3,
            ]);
            let return_address = unsafe { code.as_ptr().add(Self::START + 0x1f) } as u64;
            let stack = Box::new([return_address, 0x7766_5544_3322]);
            Self { code, stack }
        }

        fn select(&self, service: u64, original: u64, artifact: bool) -> u64 {
            unsafe {
                super::dispatcher_target_for_process(
                    self.stack[0],
                    service,
                    self.stack.as_ptr() as u64,
                    original,
                    artifact,
                )
            }
        }

        fn raw_address(&self) -> u64 {
            (unsafe { self.code.as_ptr().add(Self::START + 0x12) }) as u64
        }
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    impl Drop for WineCallStub {
        fn drop(&mut self) {
            super::super::reflex_markers::cancel(
                unsafe { libc::gettid() as u64 },
                self.stack.as_ptr() as u64 + 8,
                self.raw_address() + 2,
            );
        }
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    fn bypass_frame() -> super::DispatcherFrame {
        super::DispatcherFrame {
            registers: [0xa1a2_a3a4_a5a6_a7a8; 15],
            flags: 0x247,
            xmm: [[0x1122_3344_5566_7788, 0x8877_6655_4433_2211]; 16],
            target: 0,
            return_address: 0,
        }
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_ordinary_bypass_uses_original_for_canonical_and_unknown_callers() {
        let fixture = WineCallStub::new();
        let marker = artitux::artifact::SYSCALL_BYPASS_MAGIC;
        let return_address = fixture.stack[0];
        for (caller, service) in [
            (return_address, WineCallStub::SERVICE),
            (1, 0x1234_5678_0000_0246),
        ] {
            let mut frame = bypass_frame();
            frame.registers[14] = service;
            frame.xmm[5] = [marker, 0xfeed_face_dead_beef];
            let original_registers = frame.registers;
            let original_xmm = frame.xmm;
            let selected = unsafe {
                super::dispatcher_target_for_frame(
                    caller,
                    service,
                    fixture.stack.as_ptr() as u64,
                    WineCallStub::ORIGINAL,
                    true,
                    marker,
                    &mut frame,
                )
            };
            assert_eq!(
                selected,
                WineCallStub::ORIGINAL,
                "a bypass must never replay raw SYSCALL"
            );
            let mut expected_registers = original_registers;
            expected_registers[14] = 0x246;
            assert_eq!(frame.registers, expected_registers);
            assert_eq!(frame.flags, 0x247);
            for (index, expected) in original_xmm.iter().enumerate() {
                assert_eq!(
                    frame.xmm[index],
                    match index {
                        4 => [0x246, 0],
                        5 => [0, 0],
                        _ => *expected,
                    }
                );
            }
        }
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_ordinary_bypass_does_not_retire_a_pending_outer_flag_frame() {
        let fixture = WineCallStub::new();
        let stack = fixture.stack.as_ptr() as u64 + 8;
        let rip = fixture.raw_address() + 2;
        assert!(super::super::artifact_flags::reserve(stack, rip));
        super::super::artifact_flags::route(stack, rip, 0x8d7, 0x202);
        let marker = artitux::artifact::SYSCALL_BYPASS_MAGIC;
        let mut frame = bypass_frame();
        frame.xmm[5] = [marker, 0xfeed_face_dead_beef];
        unsafe {
            super::dispatcher_target_for_frame(
                fixture.stack[0],
                WineCallStub::SERVICE,
                fixture.stack.as_ptr() as u64,
                WineCallStub::ORIGINAL,
                true,
                marker,
                &mut frame,
            );
        }
        let saved = super::super::artifact_flags::bypass(stack, rip)
            .expect("ordinary bypass must not retire or reserve raw replay state");
        assert_eq!((saved.r11, saved.eflags), (0x8d7, 0x202));
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_ordinary_bypass_leaves_non_target_and_unmarked_frames_unchanged() {
        let fixture = WineCallStub::new();
        for (artifact, marker) in [
            (false, artitux::artifact::SYSCALL_BYPASS_MAGIC),
            (true, 0x1337_1337_1337_1337),
        ] {
            let mut frame = bypass_frame();
            frame.xmm[5][0] = marker;
            let (registers, xmm, flags) = (frame.registers, frame.xmm, frame.flags);
            let selected = unsafe {
                super::dispatcher_target_for_frame(
                    1,
                    0x1234_5678_0000_0246,
                    fixture.stack.as_ptr() as u64,
                    WineCallStub::ORIGINAL,
                    artifact,
                    marker,
                    &mut frame,
                )
            };
            assert_eq!(selected, WineCallStub::ORIGINAL);
            assert_eq!(
                (frame.registers, frame.xmm, frame.flags),
                (registers, xmm, flags)
            );
        }
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[unsafe(naked)]
    unsafe extern "C" fn owned_bypass_original_dispatcher() {
        // Owned original-dispatcher stand-in records its actual incoming
        // state and returns a real, read-only Linux getpid result.
        core::arch::naked_asm!(
            "mov [rdi], rax",
            "mov [rdi + 8], rcx",
            "mov [rdi + 16], r11",
            "mov [rdi + 24], rsp",
            "pushfq",
            "pop qword ptr [rdi + 32]",
            "movdqu [rdi + 40], xmm4",
            "movdqu [rdi + 56], xmm5",
            "mov eax, 39",
            "syscall",
            "ret",
        );
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_ordinary_bypass_machine_bridge_preserves_real_outcome_flags_and_stack() {
        const CHILD: &str = "ARTITUX_UNIT_ORDINARY_BYPASS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .args(["--exact", "syscall::kuser_dispatch::tests::artifact_ordinary_bypass_machine_bridge_preserves_real_outcome_flags_and_stack", "--test-threads=1"])
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let mut teb = [0u64; 0x80];
        teb[0x48 / 8] = 0x1a0;
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb.as_mut_ptr()) },
            0
        );
        crate::artifact::mark_detected();
        crate::artifact_loader::arm_for_test();
        crate::artifact::cpuid(0x1337, 0, 1, artitux::cpuid::Vendor::Amd, false);
        crate::artifact::cpuid(0x336933, 0x1234_0000, 0, artitux::cpuid::Vendor::Amd, false);
        assert!(crate::artifact::active());
        assert_eq!(crate::artifact::syscall_target(), Some(0x1234_0000));
        super::ORIGINAL_DISPATCHER.store(
            owned_bypass_original_dispatcher as *const () as u64,
            core::sync::atomic::Ordering::Release,
        );
        let mut capture = [0u64; 13];
        let marker = [
            artitux::artifact::SYSCALL_BYPASS_MAGIC,
            0xfeed_face_dead_beef,
        ];
        unsafe {
            core::arch::asm!(
                "mov [rdi + 72], rsp",
                "push 0x247", "popfq", "pushfq", "pop qword ptr [rdi + 80]",
                "mov rax, 0x1234567800000246",
                "mov rcx, 0x1122334455667788", "mov r11, 0x8877665544332211",
                "movdqu xmm5, [rsi]", "call r12",
                "mov [rdi + 88], rsp", "mov [rdi + 96], rax",
                in("rdi") capture.as_mut_ptr(), in("rsi") marker.as_ptr(),
                in("r12") super::dispatcher_bridge as *const (),
                clobber_abi("C"),
            );
        }
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, 0usize) },
            0
        );
        assert_eq!(capture[0], 0x246);
        assert_eq!(capture[1], 0x1122_3344_5566_7788);
        assert_eq!(capture[2], 0x8877_6655_4433_2211);
        assert_eq!(capture[3], capture[9] - 8);
        assert_eq!(capture[4], capture[10]);
        assert_eq!(&capture[5..7], &[0x246, 0]);
        assert_eq!(&capture[7..9], &[0, 0]);
        assert_eq!(capture[9], capture[11]);
        assert_eq!(capture[12], unsafe { libc::getpid() } as u64);
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_dispatcher_replays_recognized_wine_call_stub_without_iat_match() {
        let fixture = WineCallStub::new();
        assert_eq!(
            fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true),
            fixture.raw_address() | super::RAW_TARGET_TAG,
        );
        assert_eq!(
            fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, false),
            WineCallStub::ORIGINAL,
        );
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_dispatcher_routes_when_reflex_marker_table_is_saturated() {
        use std::time::{Duration, Instant};

        const CHILD_ENV: &str = "ARTITUX_UNIT_ARTIFACT_SATURATION_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            // This exact test was self-execed in an isolated test process.
            // Filling its real marker table cannot starve parallel tests.
            let fixture = WineCallStub::new();
            let mut signal_fixture = super::super::sigsys_router::artifact_tests::Fixture::new(2);
            let rsp = fixture.stack.as_ptr() as u64 + 8;
            let expected = fixture.raw_address();
            let recognized =
                super::find_artifact_wine_syscall(fixture.stack[0], WineCallStub::SERVICE)
                    == Some(expected);
            let mut saturated = false;
            for index in 0..65_536u64 {
                let tid = 0xf000_0000_0000_0000 | (index + 1);
                let stack = 0x1000 + index * 16;
                let rip = 0x2000 + index * 16;
                if !super::super::reflex_markers::remember_marker(tid, stack, rip) {
                    saturated = true;
                    break;
                }
            }
            let selected = fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true);
            let status = if !recognized {
                12
            } else if !saturated {
                10
            } else if selected != (expected | super::RAW_TARGET_TAG) {
                11
            } else {
                let outcome =
                    signal_fixture.saturated_roundtrip(rsp, expected + 2, WineCallStub::SERVICE);
                if outcome != 0 {
                    outcome
                } else if fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true)
                    != (expected | super::RAW_TARGET_TAG)
                {
                    20
                } else {
                    let repeated = signal_fixture.saturated_reused_site(
                        rsp,
                        expected + 2,
                        WineCallStub::SERVICE,
                    );
                    if repeated == 0 { 42 } else { repeated }
                }
            };
            unsafe { libc::_exit(status) };
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("syscall::kuser_dispatch::tests::artifact_dispatcher_routes_when_reflex_marker_table_is_saturated")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .env_remove("ARTITUX_DEBUG")
            .env_remove("ARTITUX_LOG")
            .env_remove("WINEPREFIX")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("marker saturation child timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            status.code(),
            Some(42),
            "child status: 10=not saturated, 11=Wine fallback, 12=invalid stub, \
             13=route declined, 14=callback ABI, 15=bypass handled, \
             16=flags/request not restored, 17=FPU state, 18=fork failure, \
             19=forked child inherited pending flags, 20-24=reused-site failure"
        );
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_dispatcher_reinstalls_after_raw_fork_rollback_without_overwriting_foreign_slot() {
        use core::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe { libc::alarm(8) };
            crate::artifact::mark_detected();
            super::BRIDGE_INSTALLED.store(false, Ordering::Release);
            super::ORIGINAL_DISPATCHER.store(0, Ordering::Release);
            let address = super::WINE_DISPATCHER_SLOT as *mut libc::c_void;
            let mapped = unsafe {
                libc::mmap(
                    address,
                    0x1000,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            if mapped != address {
                unsafe { libc::_exit(20) };
            }
            let slot = mapped.cast::<u64>();
            unsafe {
                core::ptr::write_bytes(mapped.cast::<u8>(), 0xa5, 0x1000);
                slot.write_volatile(WineCallStub::ORIGINAL);
            }
            if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ) } != 0 {
                unsafe { libc::_exit(21) };
            }
            let bridge = super::dispatcher_bridge as *const () as u64;
            if !super::install() || unsafe { slot.read_volatile() } != bridge {
                unsafe { libc::_exit(22) };
            }

            // Warm process-memory's PID before a raw fork between bridge
            // installation and provider commit. SYS_fork bypasses atfork.
            if crate::procmem::read_u64(super::WINE_DISPATCHER_SLOT) != Some(bridge) {
                unsafe { libc::_exit(34) };
            }
            let grandchild = unsafe { libc::syscall(libc::SYS_fork) } as libc::pid_t;
            if grandchild < 0 {
                unsafe { libc::_exit(23) };
            }
            if grandchild == 0 {
                unsafe { libc::alarm(5) };
                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ | libc::PROT_WRITE) }
                    != 0
                {
                    unsafe { libc::_exit(24) };
                }
                // Model the provider's child rollback of its staged page.
                unsafe { slot.write_volatile(WineCallStub::ORIGINAL) };
                let canary = unsafe { mapped.cast::<u8>().add(0x20).cast::<u32>() };
                let wrote_self = crate::procmem::write_u32(canary as u64, 0x4433_2211)
                    && unsafe { canary.read_volatile() } == 0x4433_2211;
                unsafe { canary.write_volatile(0xa5a5_a5a5) };
                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ) } != 0 {
                    unsafe { libc::_exit(25) };
                }
                let read_self = crate::procmem::read_u64(super::WINE_DISPATCHER_SLOT)
                    == Some(WineCallStub::ORIGINAL);
                let installed = super::install();
                if !read_self {
                    unsafe { libc::_exit(35) };
                }
                if !wrote_self {
                    unsafe { libc::_exit(36) };
                }
                if !installed || unsafe { slot.read_volatile() } != bridge {
                    unsafe { libc::_exit(26) };
                }
                if unsafe { mapped.cast::<u8>().add(0x20).read() } != 0xa5 {
                    unsafe { libc::_exit(27) };
                }

                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ | libc::PROT_WRITE) }
                    != 0
                {
                    unsafe { libc::_exit(28) };
                }
                let foreign = 0x3344_5566_7788u64;
                unsafe { slot.write_volatile(foreign) };
                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ) } != 0 {
                    unsafe { libc::_exit(29) };
                }
                if super::install() || unsafe { slot.read_volatile() } != foreign {
                    unsafe { libc::_exit(30) };
                }
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            loop {
                let waited = unsafe { libc::waitpid(grandchild, &mut status, 0) };
                if waited == grandchild {
                    break;
                }
                if waited < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                    unsafe { libc::_exit(31) };
                }
            }
            if !libc::WIFEXITED(status) {
                unsafe { libc::_exit(32) };
            }
            let result = libc::WEXITSTATUS(status);
            if result != 0 {
                unsafe { libc::_exit(result) };
            }
            if unsafe { slot.read_volatile() } != bridge
                || unsafe { mapped.cast::<u8>().add(0x20).read() } != 0xa5
            {
                unsafe { libc::_exit(33) };
            }
            unsafe { libc::_exit(0) };
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited == child {
                break;
            }
            if waited < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    panic!("waitpid failed: {error}");
                }
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                    libc::waitpid(child, &mut status, 0);
                }
                panic!("dispatcher install child timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            libc::WIFEXITED(status),
            "dispatcher child terminated: {status:#x}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child status 26=rollback ignored, 30=foreign slot accepted, \
             35=raw-fork self-read used another PID, 36=raw-fork self-write \
             used another PID; 20-25,27-29,31-34=fixture/setup failures"
        );
    }

    #[cfg(all(feature = "artifact", not(miri)))]
    #[test]
    fn artifact_dispatcher_falls_back_for_wrong_service_signature_or_missing_wine_target() {
        let mut fixture = WineCallStub::new();
        assert_eq!(
            fixture.select(WineCallStub::SERVICE + 1, WineCallStub::ORIGINAL, true),
            WineCallStub::ORIGINAL
        );
        assert_eq!(fixture.select(WineCallStub::SERVICE, 0, true), 0);
        for offset in [0, 0x0b, 0x18, 0x1d] {
            let byte = WineCallStub::START + offset;
            fixture.code[byte] ^= 1;
            assert_eq!(
                fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true),
                WineCallStub::ORIGINAL,
                "corrupted Wine stub offset {offset:#x}",
            );
            fixture.code[byte] ^= 1;
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_dispatcher_install_preserves_mapping_permissions_and_unrelated_bytes() {
        use core::sync::atomic::{AtomicU64, Ordering};

        struct Page(*mut u8);
        impl Drop for Page {
            fn drop(&mut self) {
                unsafe { libc::munmap(self.0.cast(), 0x1000) };
            }
        }
        fn permissions(address: u64) -> String {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .lines()
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let (start, end) = fields.next()?.split_once('-')?;
                    let start = u64::from_str_radix(start, 16).ok()?;
                    let end = u64::from_str_radix(end, 16).ok()?;
                    (start <= address && address < end).then(|| fields.next().unwrap().to_owned())
                })
                .expect("test page is mapped")
        }

        for (protection, expected) in [
            (libc::PROT_READ, "r--p"),
            (libc::PROT_READ | libc::PROT_WRITE, "rw-p"),
            (libc::PROT_READ | libc::PROT_EXEC, "r-xp"),
            (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, "rwxp"),
        ] {
            let mapping = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    0x1000,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let page = Page(mapping.cast());
            let slot = unsafe { page.0.add(16).cast::<u64>() };
            unsafe {
                core::ptr::write_bytes(page.0, 0xa5, 0x1000);
                slot.write(0x1122_3344_5566_7788);
            }
            assert_eq!(unsafe { libc::mprotect(mapping, 0x1000, protection) }, 0);
            assert_eq!(permissions(page.0 as u64), expected);

            let saved = AtomicU64::new(0);
            assert!(unsafe {
                super::swap_dispatcher_slot(slot, 0x8877_6655_4433_2211, &saved, None)
            });
            assert_eq!(saved.load(Ordering::Acquire), 0x1122_3344_5566_7788);
            assert_eq!(unsafe { slot.read() }, 0x8877_6655_4433_2211);
            assert_eq!(permissions(page.0 as u64), expected);
            for offset in [0, 8, 24, 0xfff] {
                assert_eq!(unsafe { page.0.add(offset).read() }, 0xa5);
            }
        }
    }

    #[test]
    fn bridge_stack_slots_are_power_of_two_and_thread_id_indexable() {
        assert!(super::BRIDGE_STACK_SLOTS.is_power_of_two());
        // Windows thread ids advance by four, so shifting by two and masking
        // gives each of the first SLOTS threads its own stack.
        let slot = |tid: u64| (tid >> 2) as usize & (super::BRIDGE_STACK_SLOTS - 1);
        assert_ne!(slot(0x150), slot(0x154));
        assert_eq!(
            slot(0x150),
            slot(0x150 + 4 * super::BRIDGE_STACK_SLOTS as u64)
        );
        // Slots are 16-byte aligned and hold room for the selector's frames.
        const { assert!(1usize << super::BRIDGE_STACK_SHIFT >= 0x4000) };
    }

    #[cfg(not(miri))]
    extern "C" fn returning_dispatcher() {}

    // Actually executes `dispatcher_bridge` as real machine code via inline
    // asm, and `arch_prctl` has no libc wrapper so it must go through a raw
    // syscall Miri doesn't support either; Miri interprets MIR, not raw
    // instructions jumped to at runtime.
    #[cfg(not(miri))]
    #[test]
    fn bridge_selector_runs_off_the_callers_stack() {
        // The bridge reads the Windows thread id from gs:[0x48], so give this
        // thread a fake TEB. GS is per-thread and unused by the test harness.
        let result = std::thread::spawn(|| {
            let mut teb = [0u64; 0x20];
            teb[0x48 / 8] = 0x154;
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb.as_mut_ptr()) },
                0
            );
            super::ORIGINAL_DISPATCHER.store(
                returning_dispatcher as *const () as u64,
                core::sync::atomic::Ordering::SeqCst,
            );
            let bridge = super::dispatcher_bridge as *const () as u64;
            let mut untouched: u64;
            // Canary the 0x1000 bytes below the stack pointer, call the bridge
            // as a Windows syscall stub would, and check that only its own
            // fixed frame (0x190 bytes, plus the call's return address)
            // changed.
            unsafe {
                core::arch::asm!(
                    "sub rsp, 0x1000",
                    "mov rdi, rsp",
                    "mov ecx, 0x200",
                    "mov rax, 0xa5a5a5a5a5a5a5a5",
                    "cld",
                    "rep stosq",
                    "add rsp, 0x1000",
                    "mov eax, 0x19",
                    "call {bridge}",
                    "lea rdi, [rsp - 0x800]",
                    "mov ecx, 0xc0",
                    "mov rax, 0xa5a5a5a5a5a5a5a5",
                    "xor r8d, r8d",
                    "repe scasq",
                    "sete r8b",
                    bridge = in(reg) bridge,
                    out("r8") untouched,
                    out("rax") _,
                    out("rcx") _,
                    out("rdi") _,
                    clobber_abi("C"),
                );
            }
            let lock_released = unsafe {
                core::ptr::addr_of!(super::BRIDGE_STACKS)
                    .cast::<u32>()
                    .add((0x154 / 4) << 13)
                    .read_volatile()
            };
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, 0usize) },
                0
            );
            (untouched, lock_released)
        })
        .join()
        .unwrap();
        assert_eq!(
            result.0, 1,
            "the caller's stack below the frame was written"
        );
        assert_eq!(result.1, 0, "the slot lock was not released");
    }
}
