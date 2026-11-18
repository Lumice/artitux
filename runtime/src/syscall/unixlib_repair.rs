//! Fixes a Reflex-specific side effect that is unrelated to syscall routing:
//! Reflex clones `ntdll.dll` and hooks every export as a `jmp`-style
//! trampoline (`ff 25 02 00 00 00 00 00`, destination at +8), including the
//! small set of Wine-only *data* exports — `__wine_unix_call_dispatcher` and
//! `__wine_unixlib_handle` — that don't exist on real Windows and hold a raw
//! function-pointer value rather than code. Wine's own `win32u.dll` resolves
//! those two symbols against whichever module the PEB currently calls
//! "ntdll.dll" — which Reflex has swapped for this clone, to hide its hooks
//! from anything that walks the loader list — and dereferences the result
//! once, expecting the real pointer value. Reading the trampoline's own `jmp`
//! instruction bytes there instead (`0xff 0x25 0x02 0x00 0x00 0x00 0x00 0x00`
//! == 0x225ff) is a real Wine/Windows divergence: these two symbols simply
//! don't exist in Microsoft's ntdll, so Reflex's blanket "hook every export"
//! approach never has anything to go wrong there on Windows.
//!
//! The fix does not touch the hook mechanism BL4 depends on. The clone's
//! trampoline for a data export still carries the address of the real
//! variable in the genuine, loaded ntdll.so as its embedded "destination"
//! (Reflex resolved that correctly when building the hook); the bug is only
//! that dereferencing the trampoline's own address yields code bytes instead
//! of the value stored there. Once found, the trampoline's first qword is
//! replaced with the live value already sitting at that destination, so
//! reading it yields data again. Everything else Reflex hooked — every real
//! Windows API — is left exactly as Reflex built it.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::mem::trampoline_destination;
use crate::procmem::{read_memory, read_u16, read_u32, write_u64};

const WINE_UNIX_CALL_DISPATCHER_EXPORT: &[u8] = b"__wine_unix_call_dispatcher";
const WINE_UNIXLIB_HANDLE_EXPORT: &[u8] = b"__wine_unixlib_handle";
const WINE_UNIXLIB_REPAIR_RETRY_INTERVAL: u64 = 4;
const WINE_UNIXLIB_REPAIR_MAX_ATTEMPTS: u64 = 256;

static WINE_UNIXLIB_REPAIR_DONE: AtomicBool = AtomicBool::new(false);
static WINE_UNIXLIB_REPAIR_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static WINE_UNIXLIB_REPAIR_LOGGED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_dec(prefix: *const core::ffi::c_char, value: u64);
}

#[cfg(all(feature = "artifact", feature = "debug"))]
unsafe extern "C" {
    fn debug_enabled() -> core::ffi::c_int;
}

#[cfg(all(feature = "artifact", feature = "debug"))]
fn runtime_debug_enabled() -> bool {
    unsafe { debug_enabled() != 0 }
}

#[cfg(all(test, feature = "artifact", feature = "debug"))]
static DIAGNOSTIC_PROBE_COUNT: AtomicU64 = AtomicU64::new(0);

fn log(message: &'static core::ffi::CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn log_dec(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_dec(prefix.as_ptr(), value) };
}

/// Called on every KUSER dispatcher hit and every registered-target-process
/// syscall until it succeeds once, since the repair can only run after
/// Reflex has built its ntdll clone (retried rather than triggered by a
/// specific event, to stay independent of Reflex's exact init ordering).
pub(super) fn maybe_repair_wine_unixlib_exports() {
    if WINE_UNIXLIB_REPAIR_DONE.load(Ordering::Acquire) {
        return;
    }
    let attempt = WINE_UNIXLIB_REPAIR_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    if attempt >= WINE_UNIXLIB_REPAIR_MAX_ATTEMPTS {
        return;
    }
    if attempt != 0 && !attempt.is_multiple_of(WINE_UNIXLIB_REPAIR_RETRY_INTERVAL) {
        return;
    }
    let mut repaired = 0usize;
    for_each_anonymous_executable_pe_image(|base| {
        repaired += repair_module_wine_unixlib_exports(base);
    });
    if repaired > 0 {
        WINE_UNIXLIB_REPAIR_DONE.store(true, Ordering::Release);
        if !WINE_UNIXLIB_REPAIR_LOGGED.swap(true, Ordering::AcqRel) {
            log(c"reflex ntdll clone: repaired Wine-internal data exports hooked as code");
            log_dec(c"reflex ntdll clone: exports repaired=", repaired as u64);
        }
    }
}

/// Every anonymous (not file-backed), writable-and-executable mapping in this
/// process whose first two bytes are `MZ`. The genuine, loaded `ntdll.dll` is
/// file-backed and is never visited; only in-memory PE clones like Reflex's
/// are candidates.
fn for_each_anonymous_executable_pe_image(mut visit: impl FnMut(u64)) {
    crate::maps::find_line(|line| {
        let Some(mapping) = crate::maps::parse(line) else {
            return false;
        };
        let permissions = mapping.permissions;
        let mut dos = [0u8; 2];
        if permissions.len() >= 3
            && permissions[1] == b'w'
            && permissions[2] == b'x'
            && mapping.path.is_empty()
            && read_memory(mapping.start, &mut dos)
            && dos == *b"MZ"
        {
            visit(mapping.start);
        }
        false
    });
}

struct ExportDirectory {
    image_size: u32,
    function_count: u32,
    directory_rva: u32,
    directory_size: u32,
    #[cfg(feature = "artifact")]
    name_rva: u32,
    name_count: u32,
    functions_rva: u32,
    names_rva: u32,
    ordinals_rva: u32,
}

fn read_export_directory(base: u64) -> Option<ExportDirectory> {
    let mut dos = [0u8; 0x40];
    if !read_memory(base, &mut dos) || dos[..2] != *b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    let mut signature = [0u8; 4];
    if pe_offset > 0x1000
        || !read_memory(base.checked_add(pe_offset)?, &mut signature)
        || signature != *b"PE\0\0"
    {
        return None;
    }
    let pe = base.checked_add(pe_offset)?;
    if read_u16(pe + 24)? != 0x20b {
        return None;
    }
    let image_size = read_u32(pe + 0x50)?;
    if !(0x1000..=0x400_0000).contains(&image_size) {
        return None;
    }
    let export_rva = read_u32(pe + 0x88)?;
    let directory_size = read_u32(pe + 0x8c)?;
    if export_rva == 0
        || directory_size < 40
        || !within_image(image_size, export_rva, directory_size as u64)
    {
        return None;
    }
    let directory = base.checked_add(u64::from(export_rva))?;
    let function_count = read_u32(directory + 0x14)?;
    let name_count = read_u32(directory + 0x18)?;
    let functions_rva = read_u32(directory + 0x1c)?;
    let names_rva = read_u32(directory + 0x20)?;
    let ordinals_rva = read_u32(directory + 0x24)?;
    if function_count == 0
        || function_count > 65536
        || name_count > 16384
        || !within_image(image_size, functions_rva, u64::from(function_count) * 4)
        || !within_image(image_size, names_rva, u64::from(name_count) * 4)
        || !within_image(image_size, ordinals_rva, u64::from(name_count) * 2)
    {
        return None;
    }
    Some(ExportDirectory {
        image_size,
        function_count,
        directory_rva: export_rva,
        directory_size,
        #[cfg(feature = "artifact")]
        name_rva: read_u32(directory + 0x0c)?,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    })
}

fn within_image(image_size: u32, rva: u32, length: u64) -> bool {
    rva != 0
        && u64::from(rva)
            .checked_add(length)
            .is_some_and(|end| end <= u64::from(image_size))
}

fn find_export_ordinal(base: u64, export: &ExportDirectory, name: &[u8]) -> Option<u32> {
    for index in 0..export.name_count {
        let name_rva = read_u32(base + u64::from(export.names_rva) + u64::from(index) * 4)?;
        if !within_image(export.image_size, name_rva, 40) {
            continue;
        }
        let mut candidate = [0u8; 40];
        if !read_memory(base + u64::from(name_rva), &mut candidate) {
            continue;
        }
        let length = candidate
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(candidate.len());
        if candidate[..length] == *name {
            let mut ordinal = [0u8; 2];
            if read_memory(
                base + u64::from(export.ordinals_rva) + u64::from(index) * 2,
                &mut ordinal,
            ) {
                let ordinal = u32::from(u16::from_le_bytes(ordinal));
                return (ordinal < export.function_count).then_some(ordinal);
            }
        }
    }
    None
}

/// If `name`'s function-table entry in this module has been overwritten with
/// a trampoline, restore it to the live value already sitting at the
/// trampoline's own recorded destination (the real symbol's address in the
/// genuine, loaded module). Returns `false`, harmlessly, if the name is
/// absent or was never hooked as a trampoline in the first place.
fn repair_named_export(base: u64, export: &ExportDirectory, name: &[u8]) -> bool {
    let Some(record) = named_export_record(base, export, name) else {
        return false;
    };
    let Some(destination) = trampoline_destination(record) else {
        return false;
    };
    let Some(value) = crate::procmem::read_u64(destination) else {
        return false;
    };
    write_u64(record, value)
}

fn named_export_record(base: u64, export: &ExportDirectory, name: &[u8]) -> Option<u64> {
    let ordinal = find_export_ordinal(base, export, name)?;
    let slot = base
        .checked_add(u64::from(export.functions_rva))?
        .checked_add(u64::from(ordinal) * 4)?;
    let rva = read_u32(slot)?;
    if !within_image(export.image_size, rva, 16)
        || (rva >= export.directory_rva && rva - export.directory_rva < export.directory_size)
    {
        return None;
    }
    base.checked_add(u64::from(rva))
}

#[cfg(feature = "artifact")]
fn named_ntdll(base: u64, export: &ExportDirectory) -> bool {
    if !within_image(export.image_size, export.name_rva, 10) {
        return false;
    }
    let mut name = [0u8; 10];
    read_memory(base + u64::from(export.name_rva), &mut name)
        && name.eq_ignore_ascii_case(b"ntdll.dll\0")
}

#[cfg(all(feature = "artifact", feature = "debug"))]
fn log_ntdll_export_probe(
    base: u64,
    parsed_prefix: &'static core::ffi::CStr,
    named_prefix: &'static core::ffi::CStr,
) {
    if !runtime_debug_enabled() {
        return;
    }
    #[cfg(test)]
    DIAGNOSTIC_PROBE_COUNT.fetch_add(1, Ordering::Relaxed);
    let parsed = read_export_directory(base);
    log_dec(parsed_prefix, parsed.is_some() as u64);
    log_dec(
        named_prefix,
        parsed.as_ref().is_some_and(|e| named_ntdll(base, e)) as u64,
    );
}

#[cfg(all(feature = "artifact", feature = "debug"))]
fn log_artifact_record_probe(record: u64, source: u64) {
    if !runtime_debug_enabled() {
        return;
    }
    #[cfg(test)]
    DIAGNOSTIC_PROBE_COUNT.fetch_add(1, Ordering::Relaxed);
    log_dec(
        c"artifact Wine data scan: record aligned=",
        record.is_multiple_of(8) as u64,
    );
    log_dec(
        c"artifact Wine data scan: exact native target=",
        (trampoline_destination(record) == Some(source)) as u64,
    );
    log_dec(
        c"artifact Wine data scan: native unhooked=",
        trampoline_destination(source).is_none() as u64,
    );
}

/// Correct only completed clones whose recorded destinations are the genuine
/// same-named Wine variables. This does not depend on the legacy retry budget.
#[cfg(feature = "artifact")]
fn repair_artifact_clone(native: u64, clone: u64) -> usize {
    if native == clone {
        #[cfg(feature = "debug")]
        log(c"artifact Wine data scan: candidate equals loader ntdll");
        return 0;
    }
    #[cfg(feature = "debug")]
    log_ntdll_export_probe(
        clone,
        c"artifact Wine data scan: candidate parsed=",
        c"artifact Wine data scan: candidate named ntdll=",
    );
    let (Some(real), Some(fake)) = (read_export_directory(native), read_export_directory(clone))
    else {
        return 0;
    };
    if !named_ntdll(native, &real) || !named_ntdll(clone, &fake) {
        return 0;
    }
    #[cfg(feature = "debug")]
    log(c"artifact Wine data scan: validated ntdll clone");
    let mut repaired = 0;
    for name in [WINE_UNIX_CALL_DISPATCHER_EXPORT, WINE_UNIXLIB_HANDLE_EXPORT] {
        let (Some(source), Some(record)) = (
            named_export_record(native, &real, name),
            named_export_record(clone, &fake, name),
        ) else {
            continue;
        };
        #[cfg(feature = "debug")]
        log_artifact_record_probe(record, source);
        if record % 8 != 0
            || trampoline_destination(record) != Some(source)
            || trampoline_destination(source).is_some()
        {
            continue;
        }
        let Some(value) = crate::procmem::read_u64(source) else {
            continue;
        };
        let before = u64::from_le_bytes(super::mem::TRAMPOLINE_HEAD);
        let mut writable = false;
        crate::maps::find_line(|line| {
            let Some(m) = crate::maps::parse(line) else {
                return false;
            };
            // A PE-declared RVA/SizeOfImage is not proof that a later
            // mapping belongs to this clone. Refuse split/foreign mappings.
            writable = m.start == clone
                && m.path.is_empty()
                && m.start <= record
                && record.checked_add(8).is_some_and(|end| end <= m.end)
                && m.permissions.len() >= 2
                && m.permissions[0] == b'r'
                && m.permissions[1] == b'w';
            writable
        });
        #[cfg(feature = "debug")]
        log_dec(
            c"artifact Wine data scan: owned writable record=",
            writable as u64,
        );
        if writable && crate::procmem::read_u64(source) == Some(value) {
            // Only the qualified aligned clone word is published, with no
            // overwrite if another initializer changed it since inspection.
            let slot = unsafe { &*(record as *const AtomicU64) };
            if slot
                .compare_exchange(before, value, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                repaired += 1;
            }
        }
    }
    repaired
}

#[cfg(feature = "artifact")]
fn native_ntdll_mapping(line: &[u8]) -> Option<u64> {
    let m = crate::maps::parse(line)?;
    let basename = m.path.rsplit(|&b| b == b'/').next()?;
    (m.permissions.first() == Some(&b'r')
        && m.inode != b"0"
        && m.path.first() == Some(&b'/')
        && basename.eq_ignore_ascii_case(b"ntdll.dll"))
    .then_some(m.start)
}

/// Artifact can insert its anonymous clone ahead of the genuine module even
/// after the loader header is restored. A first loader-list match is therefore
/// not native-origin evidence. Require a unique named, file-backed PE instead.
#[cfg(feature = "artifact")]
fn native_ntdll_from_mappings() -> Option<u64> {
    let mut native = None;
    let mut ambiguous = false;
    crate::maps::find_line(|line| {
        let Some(base) = native_ntdll_mapping(line) else {
            return false;
        };
        let Some(export) = read_export_directory(base) else {
            return false;
        };
        if !named_ntdll(base, &export) {
            return false;
        }
        if native.is_some_and(|previous| previous != base) {
            ambiguous = true;
        }
        native = Some(base);
        false
    });
    if ambiguous { None } else { native }
}

#[cfg(feature = "artifact")]
pub(super) fn repair_completed_artifact_exports() -> usize {
    let Some(native) = native_ntdll_from_mappings() else {
        #[cfg(feature = "debug")]
        log(c"artifact Wine data scan: unique file-backed ntdll missing");
        return 0;
    };
    #[cfg(feature = "debug")]
    log_ntdll_export_probe(
        native,
        c"artifact Wine data scan: file-backed ntdll parsed=",
        c"artifact Wine data scan: file-backed ntdll named=",
    );
    let mut repaired = 0;
    let mut visited = 0;
    for_each_anonymous_executable_pe_image(|base| {
        visited += 1;
        if visited <= 128 {
            repaired += repair_artifact_clone(native, base);
        }
    });
    #[cfg(feature = "debug")]
    log_dec(
        c"artifact Wine data scan: anonymous PE candidates=",
        visited as u64,
    );
    repaired
}

fn repair_module_wine_unixlib_exports(base: u64) -> usize {
    let Some(export) = read_export_directory(base) else {
        return 0;
    };
    [WINE_UNIX_CALL_DISPATCHER_EXPORT, WINE_UNIXLIB_HANDLE_EXPORT]
        .into_iter()
        .filter(|name| repair_named_export(base, &export, name))
        .count()
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::{find_export_ordinal, read_export_directory, read_memory, repair_named_export};

    /// A minimal PE image with a real export table, real memory backing it
    /// (`process_vm_readv`/`writev` validate against the process's actual
    /// page tables, so a plain byte buffer won't do), holding one export
    /// whose function-table entry has been overwritten with a Reflex-style
    /// trampoline. Layout is arbitrary but self-consistent; only the RVAs
    /// wired up here are read.
    struct FakePeExport {
        base: u64,
        length: usize,
    }

    impl FakePeExport {
        fn new(name: &[u8], hooked: bool) -> Self {
            Self::with_length(name, hooked, 0x1000)
        }

        fn with_length(name: &[u8], hooked: bool, length: usize) -> Self {
            let base = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            } as u64;
            assert_ne!(base, u64::MAX, "mmap failed");
            let write = |offset: usize, bytes: &[u8]| unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (base as *mut u8).add(offset),
                    bytes.len(),
                );
            };
            // DOS header: e_lfanew -> 0x80.
            write(0, b"MZ");
            write(0x3c, &0x80u32.to_le_bytes());
            // PE header, export directory RVA at +0x88 -> 0x200.
            write(0x80, b"PE\0\0");
            write(0x80 + 24, &0x20bu16.to_le_bytes());
            write(0x80 + 0x50, &0x1000u32.to_le_bytes());
            write(0x80 + 0x88, &0x200u32.to_le_bytes());
            write(0x80 + 0x8c, &0x40u32.to_le_bytes());
            write(0x200 + 0x0c, &0x350u32.to_le_bytes());
            write(0x350, b"ntdll.dll\0");
            write(0x200 + 0x14, &1u32.to_le_bytes());
            // Export directory occupies 0x200..0x228; every table it points
            // at lives past that so none of these writes overlap each other.
            write(0x200 + 0x18, &1u32.to_le_bytes()); // NumberOfNames
            write(0x200 + 0x1c, &0x300u32.to_le_bytes()); // AddressOfFunctions
            write(0x200 + 0x20, &0x320u32.to_le_bytes()); // AddressOfNames
            write(0x200 + 0x24, &0x340u32.to_le_bytes()); // AddressOfNameOrdinals
            write(0x300, &0x500u32.to_le_bytes()); // functions[0] -> 0x500
            write(0x320, &0x360u32.to_le_bytes()); // names[0] -> the string
            write(0x340, &0u16.to_le_bytes()); // ordinals[0] -> 0
            write(0x360, name);
            write(0x360 + name.len(), &[0]);
            // The "real" value a correctly resolved data export would hold.
            write(0x600, &0xdead_beef_cafe_f00du64.to_le_bytes());
            if hooked {
                write(0x500, &super::super::mem::TRAMPOLINE_HEAD);
                // The embedded destination is an absolute address (as Reflex
                // writes it), not an RVA, so it must be `base`-relative here.
                write(0x500 + 8, &(base + 0x600).to_le_bytes());
            } else {
                write(0x500, &0xdead_beef_cafe_f00du64.to_le_bytes());
            }
            Self { base, length }
        }
    }

    impl Drop for FakePeExport {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.base as *mut libc::c_void, self.length) };
        }
    }

    // `read_export_directory`/`repair_named_export`/`read_memory` all read
    // through `super::mem`, which calls `process_vm_readv` — not in Miri's
    // foreign-function shim list at all.
    #[cfg(not(miri))]
    #[test]
    fn repair_replaces_a_hooked_data_exports_trampoline_with_its_real_value() {
        let name = b"__wine_unix_call_dispatcher";
        let image = FakePeExport::new(name, true);
        let export = read_export_directory(image.base).expect("export directory parses");

        assert_eq!(find_export_ordinal(image.base, &export, name), Some(0));
        assert_eq!(
            find_export_ordinal(image.base, &export, b"not_present"),
            None
        );

        assert!(repair_named_export(image.base, &export, name));
        let mut repaired = [0u8; 8];
        assert!(read_memory(image.base + 0x500, &mut repaired));
        assert_eq!(u64::from_le_bytes(repaired), 0xdead_beef_cafe_f00d);

        // Idempotent: once repaired, the slot no longer looks like a
        // trampoline, so a second pass is a harmless no-op.
        assert!(!repair_named_export(image.base, &export, name));
    }

    // Same as above: goes through `super::mem`'s `process_vm_readv`-based
    // reads, which Miri doesn't emulate at all.
    #[cfg(not(miri))]
    #[test]
    fn repair_leaves_an_unhooked_data_export_alone() {
        let name = b"__wine_unixlib_handle";
        let image = FakePeExport::new(name, false);
        let export = read_export_directory(image.base).expect("export directory parses");

        assert!(!repair_named_export(image.base, &export, name));
        let mut untouched = [0u8; 8];
        assert!(read_memory(image.base + 0x500, &mut untouched));
        assert_eq!(u64::from_le_bytes(untouched), 0xdead_beef_cafe_f00d);
    }
    #[cfg(feature = "artifact")]
    #[test]
    fn completed_artifact_clone_repairs_only_exact_native_data_targets() {
        for name in [
            b"__wine_unix_call_dispatcher".as_slice(),
            b"__wine_unixlib_handle".as_slice(),
        ] {
            let native = FakePeExport::new(name, false);
            let clone = FakePeExport::new(name, true);
            // Same-valued foreign storage is not evidence of native-variable origin.
            assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
            unsafe { ((clone.base + 0x508) as *mut u64).write(native.base + 0x500) };
            assert_eq!(super::repair_artifact_clone(native.base, clone.base), 1);
            assert_eq!(
                crate::procmem::read_u64(clone.base + 0x500),
                Some(0xdead_beef_cafe_f00d)
            );
            assert_eq!(
                crate::procmem::read_u64(native.base + 0x500),
                Some(0xdead_beef_cafe_f00d)
            );
            assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
            assert_eq!(super::repair_artifact_clone(native.base, native.base), 0);
        }
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn native_ntdll_origin_requires_readable_named_file_mapping() {
        for (line, expected) in [
            (
                b"1000-2000 r--p 00000000 00:01 1 /Wine prefix/system32/ntdll.dll".as_slice(),
                Some(0x1000),
            ),
            (
                b"1000-2000 r-xp 00000000 00:01 1 /system32/NTDLL.DLL".as_slice(),
                Some(0x1000),
            ),
            (b"1000-2000 rwxp 00000000 00:00 0".as_slice(), None),
            (
                b"1000-2000 rwxp 00000000 00:00 0 [anon:ntdll.dll]".as_slice(),
                None,
            ),
            (
                b"1000-2000 r--p 00000000 00:01 1 /system32/otherntdll.dll".as_slice(),
                None,
            ),
            (
                b"1000-2000 --xp 00000000 00:01 1 /system32/ntdll.dll".as_slice(),
                None,
            ),
        ] {
            assert_eq!(super::native_ntdll_mapping(line), expected);
        }
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn completed_artifact_clone_refuses_record_in_separate_mapping() {
        let name = b"__wine_unixlib_handle";
        let native = FakePeExport::new(name, false);
        let clone = FakePeExport::with_length(name, true, 0x3000);
        unsafe {
            ((clone.base + 0x80 + 0x50) as *mut u32).write(0x3000);
            ((clone.base + 0x300) as *mut u32).write(0x2500);
            ((clone.base + 0x2500) as *mut u64)
                .write(u64::from_le_bytes(super::super::mem::TRAMPOLINE_HEAD));
            ((clone.base + 0x2508) as *mut u64).write(native.base + 0x500);
            // An inaccessible middle page splits the foreign writable record
            // from the mapping containing the candidate's PE header.
            assert_eq!(
                libc::mprotect((clone.base + 0x1000) as *mut _, 0x1000, libc::PROT_NONE),
                0
            );
        }
        let before = crate::procmem::read_u64(clone.base + 0x2500);
        assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
        assert_eq!(crate::procmem::read_u64(clone.base + 0x2500), before);
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn completed_artifact_clone_refuses_foreign_malformed_and_readonly_images() {
        let name = b"__wine_unixlib_handle";
        let native = FakePeExport::new(name, false);
        let clone = FakePeExport::new(name, true);
        unsafe { ((clone.base + 0x508) as *mut u64).write(native.base + 0x500) };
        let before = crate::procmem::read_u64(clone.base + 0x500);
        unsafe { ((clone.base + 0x350) as *mut u8).write(b'x') };
        assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
        unsafe { ((clone.base + 0x350) as *mut u8).write(b'n') };
        unsafe { ((clone.base + 0x80 + 0x50) as *mut u32).write(0x200) };
        assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
        unsafe { ((clone.base + 0x80 + 0x50) as *mut u32).write(0x1000) };
        unsafe { ((clone.base + 0x218) as *mut u32).write(u32::MAX) };
        assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
        unsafe { ((clone.base + 0x218) as *mut u32).write(1) };
        assert_eq!(
            unsafe { libc::mprotect(clone.base as *mut _, clone.length, libc::PROT_READ) },
            0
        );
        assert_eq!(super::repair_artifact_clone(native.base, clone.base), 0);
        assert_eq!(crate::procmem::read_u64(clone.base + 0x500), before);
    }

    #[cfg(all(feature = "artifact", feature = "debug"))]
    #[test]
    fn artifact_diagnostic_probes_respect_runtime_debug_gate() {
        if let Some(expected) = std::env::var_os("ARTITUX_UNIXLIB_DIAG_GATE_CHILD") {
            let name = b"__wine_unixlib_handle";
            let native = FakePeExport::new(name, false);
            let clone = FakePeExport::new(name, true);
            unsafe { ((clone.base + 0x508) as *mut u64).write(native.base + 0x500) };
            super::DIAGNOSTIC_PROBE_COUNT.store(0, core::sync::atomic::Ordering::Relaxed);
            assert_eq!(super::repair_artifact_clone(native.base, clone.base), 1);
            let expected_probes = if expected == "1" { 2 } else { 0 };
            assert_eq!(
                super::DIAGNOSTIC_PROBE_COUNT.load(core::sync::atomic::Ordering::Relaxed),
                expected_probes
            );
            assert_eq!(
                crate::procmem::read_u64(clone.base + 0x500),
                Some(0xdead_beef_cafe_f00d)
            );
            return;
        }
        for mode in ["0", "1"] {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.env("ARTITUX_UNIXLIB_DIAG_GATE_CHILD", mode)
                .env_remove("ARTITUX_LOG");
            if mode == "1" {
                cmd.env("ARTITUX_DEBUG", "1");
            } else {
                cmd.env_remove("ARTITUX_DEBUG");
            }
            let output = cmd
                .args([
                    "--exact",
                    "syscall::unixlib_repair::tests::artifact_diagnostic_probes_respect_runtime_debug_gate",
                    "--test-threads=1",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child mode {mode} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
