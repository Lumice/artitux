//! The SIGSYS boundary: Artitux's own syscall-trap handler, installed by
//! `hooks.rs` alongside the CPUID SIGSEGV handler. Given a trapped syscall,
//! this forwards ordinary calls to Wine, routes Reflex-evidenced calls to
//! Reflex, and routes positively registered ART SYS_USER_DISPATCH calls to
//! ART's callback. Each protocol has its own bypass and register contract.
//!
//! This module is always compiled, independent of the `kuser`/`reflex`
//! features: without a matching registration or bridge, calls fall through
//! to Wine. The marker bookkeeping this boundary reads
//! ([`super::reflex_markers`]) lives in its own file because it needs that
//! narrower feature gate; this file owns the decision, not the storage.

use artitux::reflex::SYSCALL_BYPASS_MAGIC;
use core::ffi::{c_int, c_void};
use core::ptr;
use libc::{siginfo_t, ucontext_t};

const SYS_SECCOMP: c_int = 1;
const SYS_USER_DISPATCH: c_int = 2;

#[cfg(feature = "artifact")]
const _: () = assert!(
    core::mem::size_of::<libc::_libc_fpstate>() == 512
        && core::mem::offset_of!(libc::_libc_fpstate, _xmm) == 160
);

#[cfg(feature = "artifact")]
enum ArtifactFpState {
    Legacy,
    Xsave(*mut u64),
}

/// Validate within the fixed legacy prefix before accessing an XSAVE header.
/// The caller supplies a live kernel frame, including its declared extension.
#[cfg(feature = "artifact")]
unsafe fn artifact_fp_state(fp: *mut libc::_libc_fpstate) -> Option<ArtifactFpState> {
    let bytes = fp.cast::<u8>();
    // SAFETY: all three metadata words are inside the fixed 512-byte prefix.
    let (magic, extent, size) = unsafe {
        (
            bytes.add(464).cast::<u32>().read_unaligned(),
            bytes.add(468).cast::<u32>().read_unaligned(),
            bytes.add(480).cast::<u32>().read_unaligned(),
        )
    };
    if magic != 0x4650_5853 {
        return Some(ArtifactFpState::Legacy);
    }
    // Linux's extended size includes the trailing FP_XSTATE_MAGIC2 word;
    // xstate_size includes the entire 64-byte XSAVE header at offset 512.
    if extent < 580 || size < 576 || size > extent - 4 {
        return None;
    }
    Some(ArtifactFpState::Xsave(unsafe { bytes.add(512).cast() }))
}

#[cfg(feature = "artifact")]
unsafe fn publish_artifact_sse(state: &ArtifactFpState) {
    if let ArtifactFpState::Xsave(header) = state {
        // SAFETY: validated kernel metadata declares a complete XSAVE header.
        // Preserve every other component bit and all extended component data.
        unsafe { header.write_unaligned(header.read_unaligned() | 2) };
    }
}

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
}

/// Bounded trace of Reflex selector routing: the syscall number, thread and
/// caller for each SIGSYS offered to Reflex, and for each bypass replay Reflex
/// hands back. A selector route with no following bypass on the same thread
/// was answered by Reflex itself; one followed by a bypass went to Wine.
#[cfg(feature = "debug")]
fn trace_reflex_hop(
    kind: &'static core::ffi::CStr,
    tid: u64,
    rip: u64,
    gregs: *const libc::greg_t,
) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static EVENTS: AtomicU64 = AtomicU64::new(0);
    if EVENTS.fetch_add(1, Ordering::Relaxed) >= 96 {
        return;
    }
    let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
    unsafe {
        debug_log(kind.as_ptr());
        debug_log_hex(c"reflex hop tid=".as_ptr(), tid);
        debug_log_hex(c"reflex hop RIP=".as_ptr(), rip);
        debug_log_hex(c"reflex hop RAX=".as_ptr(), register(libc::REG_RAX));
        debug_log_hex(c"reflex hop R10=".as_ptr(), register(libc::REG_R10));
        debug_log_hex(c"reflex hop RDX=".as_ptr(), register(libc::REG_RDX));
        debug_log_hex(c"reflex hop R8=".as_ptr(), register(libc::REG_R8));
    }
}

/// Keep a separate, small budget for the window-list service: the general
/// Reflex trace is usually exhausted before game initialization reaches it.
/// The seventh and eighth Windows arguments live on the caller's stack.
#[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
fn trace_window_list(kind: &'static core::ffi::CStr, gregs: *const libc::greg_t) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static EVENTS: AtomicU64 = AtomicU64::new(0);
    let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
    if register(libc::REG_RAX) != 0x132d || EVENTS.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    let rsp = register(libc::REG_RSP);
    unsafe {
        debug_log(kind.as_ptr());
        debug_log_hex(c"window list RIP=".as_ptr(), register(libc::REG_RIP));
        debug_log_hex(c"window list RSP=".as_ptr(), rsp);
        debug_log_hex(c"window list R10=".as_ptr(), register(libc::REG_R10));
        debug_log_hex(c"window list RDX=".as_ptr(), register(libc::REG_RDX));
        debug_log_hex(c"window list R8=".as_ptr(), register(libc::REG_R8));
        debug_log_hex(c"window list R9=".as_ptr(), register(libc::REG_R9));
        if let Some(value) = crate::procmem::read_u64(rsp.saturating_add(0x38)) {
            debug_log_hex(c"window list stack+0x38=".as_ptr(), value);
        }
        if let Some(value) = crate::procmem::read_u64(rsp.saturating_add(0x40)) {
            debug_log_hex(c"window list stack+0x40=".as_ptr(), value);
        }
    }
}

unsafe extern "C" {
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn reflex_route_syscall(
        context: *const ucontext_t,
        target: *mut u64,
        rax_is_resume: *mut c_int,
    ) -> c_int;
}

#[derive(Clone, Copy)]
struct Route {
    target: u64,
    rax_is_resume: bool,
}

fn is_bypass(xmm5: &[u8; 16]) -> bool {
    u64::from_le_bytes(xmm5[..8].try_into().unwrap()) == SYSCALL_BYPASS_MAGIC
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscallhook(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    let _errno = crate::errno::Errno::save();
    let handled = if info.is_null() || context.is_null() {
        false
    } else {
        unsafe {
            let context = context.cast::<ucontext_t>();
            #[cfg(feature = "artifact")]
            let _dispatch_guard = crate::artifact::wine_dispatch_guard();
            #[cfg(feature = "artifact")]
            let artifact_target = if crate::artifact::active() {
                crate::artifact::syscall_target()
            } else {
                None
            };
            #[cfg(not(feature = "artifact"))]
            let artifact_target = None;
            redirect(info, context, artifact_target, |ctx| {
                let mut target = 0;
                let mut rax_is_resume = 0;
                (reflex_route_syscall(ctx, &mut target, &mut rax_is_resume) != 0).then_some(Route {
                    target,
                    rax_is_resume: rax_is_resume != 0,
                })
            })
        }
    };
    if !handled {
        unsafe { forward_signal(sig, info, context) };
    }
}

unsafe fn redirect(
    info: *const siginfo_t,
    context: *mut ucontext_t,
    artifact_target: Option<u64>,
    route: impl FnOnce(*const ucontext_t) -> Option<Route>,
) -> bool {
    if info.is_null() || context.is_null() {
        return false;
    }
    let fpregs = unsafe { ptr::addr_of!((*context).uc_mcontext.fpregs).read() };
    if fpregs.is_null() {
        return false;
    }
    let code = unsafe { ptr::addr_of!((*info).si_code).read() };
    if !matches!(code, SYS_SECCOMP | SYS_USER_DISPATCH) {
        return false;
    }
    // ART's contract covers SUD only. In particular, seccomp traps must not
    // consume an ART bridge marker or enter Reflex's unrelated magic path.
    #[cfg(feature = "artifact")]
    if artifact_target.is_some() && code != SYS_USER_DISPATCH {
        return false;
    }
    #[cfg(feature = "artifact")]
    let artifact_fpstate = if artifact_target.is_some() {
        // Refuse malformed extended metadata before changing any registers or
        // consuming a pending marker. Old-style FXSAVE needs no header write.
        let Some(state) = (unsafe { artifact_fp_state(fpregs) }) else {
            return false;
        };
        state
    } else {
        ArtifactFpState::Legacy
    };
    let xmm = unsafe { ptr::addr_of_mut!((*fpregs)._xmm).cast::<[u8; 16]>() };
    let xmm5 = unsafe { xmm.add(5).read() };
    let gregs = unsafe { ptr::addr_of_mut!((*context).uc_mcontext.gregs).cast::<libc::greg_t>() };
    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() as u64 };
    // Every branch below needs the current thread id at least once, and some
    // need it two or three times; `gettid` is a real syscall (not the cached
    // libc wrapper), so query it once per event rather than per use.
    let tid = unsafe { libc::gettid() as u64 };
    // Every use below is gated by some combination of `kuser`/`reflex`/
    // `debug`; with all three off, `tid` itself would otherwise be unused.
    let _ = tid;
    #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
    let trace_event = {
        let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
        super::diagnostics::event(
            tid,
            code as u64,
            super::diagnostics::Disposition::Forwarded,
            [
                rip,
                register(libc::REG_RSP),
                register(libc::REG_RAX),
                register(libc::REG_R10),
                register(libc::REG_RCX),
                register(libc::REG_RDX),
                register(libc::REG_R8),
                register(libc::REG_R9),
                register(libc::REG_R13),
                u64::from_le_bytes(xmm5[..8].try_into().unwrap()),
            ],
        )
    };
    // `bridged` only exists under kuser+reflex (its type, `reflex_markers::
    // Phase`, is only compiled then) — every read of it below is gated by
    // the same features, so it is simply not declared otherwise, rather
    // than given a placeholder `None` with no type for the compiler to
    // infer from unused dead code.
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    let bridged = super::reflex_markers::consume(
        tid,
        unsafe { gregs.add(libc::REG_RSP as usize).read() as u64 },
        rip,
        unsafe { xmm.add(4).read() },
        xmm5,
        unsafe { gregs.add(libc::REG_R11 as usize).read() as u64 },
        unsafe { gregs.add(libc::REG_EFL as usize).read() as u64 },
    );
    #[cfg(feature = "artifact")]
    if code == SYS_USER_DISPATCH
        && let Some(target) = artifact_target
    {
        let rsp = unsafe { gregs.add(libc::REG_RSP as usize).read() as u64 };
        let bypass = u64::from_le_bytes(xmm5[..8].try_into().unwrap())
            == artitux::artifact::SYSCALL_BYPASS_MAGIC;
        let service = unsafe { gregs.add(libc::REG_RAX as usize).read() as u32 };
        let mut xmm4 = [0u8; 16];
        xmm4[..4].copy_from_slice(&service.to_le_bytes());
        unsafe { xmm.add(4).write(xmm4) };
        unsafe { publish_artifact_sse(&artifact_fpstate) };

        if bypass {
            let mut saved_flags =
                super::artifact_flags::bypass(rsp, rip).map(|saved| (saved.r11, saved.eflags));
            #[cfg(all(feature = "kuser", feature = "reflex"))]
            {
                match bridged {
                    Some(super::reflex_markers::Phase::Replay(saved)) => {
                        if saved_flags.is_none() {
                            saved_flags = Some((saved.r11, saved.eflags));
                        }
                    }
                    Some(super::reflex_markers::Phase::Route) => {
                        super::reflex_markers::cancel(tid, rsp, rip);
                    }
                    None => {}
                }
                super::reflex_markers::retire_markers(tid, rsp);
            }
            if let Some((r11, eflags)) = saved_flags {
                unsafe {
                    gregs.add(libc::REG_R11 as usize).write(r11 as libc::greg_t);
                    gregs
                        .add(libc::REG_EFL as usize)
                        .write(eflags as libc::greg_t);
                }
            }
            unsafe {
                xmm.add(5).write([0; 16]);
                gregs
                    .add(libc::REG_RAX as usize)
                    .write(libc::greg_t::from(service));
            }
            return false;
        }

        super::artifact_flags::route(
            rsp,
            rip,
            unsafe { gregs.add(libc::REG_R11 as usize).read() as u64 },
            unsafe { gregs.add(libc::REG_EFL as usize).read() as u64 },
        );

        #[cfg(all(feature = "kuser", feature = "reflex"))]
        match bridged {
            Some(super::reflex_markers::Phase::Route) => {}
            Some(super::reflex_markers::Phase::Replay(_)) => {
                // A handler may complete without bypassing. A later call can
                // reuse the same RIP and RSP, so Replay is not proof of a
                // bypass. Save this new call's flags for its own replay.
                super::reflex_markers::retire_markers(tid, rsp);
                if super::reflex_markers::remember_marker(tid, rsp, rip) {
                    let _ = super::reflex_markers::consume(
                        tid,
                        rsp,
                        rip,
                        xmm4,
                        xmm5,
                        unsafe { gregs.add(libc::REG_R11 as usize).read() as u64 },
                        unsafe { gregs.add(libc::REG_EFL as usize).read() as u64 },
                    );
                }
            }
            None => super::reflex_markers::retire_markers(tid, rsp),
        }

        unsafe {
            let r11 = gregs.add(libc::REG_R11 as usize).read();
            gregs.add(libc::REG_EFL as usize).write(r11);
            gregs.add(libc::REG_RAX as usize).write(rip as libc::greg_t);
            gregs
                .add(libc::REG_RCX as usize)
                .write(target as libc::greg_t);
            gregs
                .add(libc::REG_RIP as usize)
                .write(target as libc::greg_t);
        }
        return true;
    }
    #[cfg(not(feature = "artifact"))]
    let _ = artifact_target;
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    if let Some(super::reflex_markers::Phase::Replay(saved)) = bridged {
        unsafe {
            xmm.add(4).write(saved.xmm4);
            xmm.add(5).write(saved.xmm5);
            gregs
                .add(libc::REG_R11 as usize)
                .write(saved.r11 as libc::greg_t);
            gregs
                .add(libc::REG_EFL as usize)
                .write(saved.eflags as libc::greg_t);
        }
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(
            trace_event.with_disposition(super::diagnostics::Disposition::BridgeReplayRestored),
        );
        return false;
    }
    if is_bypass(&xmm5) {
        #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
        trace_window_list(c"window list Reflex bypass", gregs);
        #[cfg(feature = "debug")]
        trace_reflex_hop(c"reflex bypass replay", tid, rip, gregs);
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        if matches!(bridged, Some(super::reflex_markers::Phase::Route)) {
            unsafe {
                super::reflex_markers::cancel(
                    tid,
                    gregs.add(libc::REG_RSP as usize).read() as u64,
                    rip,
                );
            }
        }
        unsafe { xmm.add(5).write([0; 16]) };
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        if code == SYS_USER_DISPATCH && super::win32u_zero_list::maybe_complete_bypass(gregs) {
            #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
            super::diagnostics::record_game_event(
                trace_event.with_disposition(super::diagnostics::Disposition::LocallyCompleted),
            );
            return true;
        }
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(
            trace_event.with_disposition(super::diagnostics::Disposition::ReflexBypassForwarded),
        );
        return false;
    }
    let is_bridged_route = {
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        {
            matches!(bridged, Some(super::reflex_markers::Phase::Route))
        }
        #[cfg(not(all(feature = "kuser", feature = "reflex")))]
        {
            false
        }
    };
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    let is_target_process_route = if is_bridged_route {
        false
    } else {
        let service = unsafe { gregs.add(libc::REG_RAX as usize).read() as u64 };
        super::reflex_markers::is_registered_target_process(rip, service)
    };
    #[cfg(not(all(feature = "kuser", feature = "reflex")))]
    let is_target_process_route = false;
    if !is_bridged_route && !is_target_process_route {
        #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
        trace_window_list(c"window list direct Wine route", gregs);
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(trace_event);
        return false;
    }
    let Some(selected_route) = route(context) else {
        #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
        trace_window_list(c"window list unselected Wine route", gregs);
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(
            trace_event.with_disposition(super::diagnostics::Disposition::ReflexRouteDeclined),
        );
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        if is_bridged_route {
            unsafe {
                super::reflex_markers::cancel(
                    tid,
                    gregs.add(libc::REG_RSP as usize).read() as u64,
                    rip,
                );
            }
        }
        return false;
    };
    #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
    trace_window_list(c"window list Reflex route", gregs);
    #[cfg(feature = "debug")]
    trace_reflex_hop(
        if is_bridged_route {
            c"reflex route (bridged)"
        } else {
            c"reflex route (target process)"
        },
        tid,
        rip,
        gregs,
    );
    #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
    super::diagnostics::record_game_event(
        trace_event.with_disposition(super::diagnostics::Disposition::ReflexRedirected),
    );
    unsafe {
        // `syscall` clears bits out of EFLAGS per the CPU's SFMASK before
        // this trap is even delivered, stashing the true pre-call value in
        // R11 (the ISA guarantee `sysret` relies on to restore it later). A
        // real `int 2e` never touches EFLAGS at all, so Reflex's own
        // hooked-syscall entry point — reverse-engineered to expect exactly
        // what `int 2e` would hand it — needs that true value here, on the
        // way in, not only restored on the bridged marker's `Phase::Replay`
        // return trip above. See syscall-routing.md's "preserve ...
        // R11/EFLAGS" invariant: it applies to both hops, not just one.
        let r11 = gregs.add(libc::REG_R11 as usize).read();
        gregs.add(libc::REG_EFL as usize).write(r11);

        let selector = gregs.add(libc::REG_RAX as usize).read() as u32;
        let mut xmm4 = xmm.add(4).read();
        xmm4[..4].copy_from_slice(&selector.to_le_bytes());
        xmm.add(4).write(xmm4);
        let rcx = gregs.add(libc::REG_RCX as usize).read() as u64;
        let rax = if selected_route.rax_is_resume {
            syscall_resume(rip, rcx)
        } else {
            rcx
        };
        gregs.add(libc::REG_RAX as usize).write(rax as libc::greg_t);
        gregs
            .add(libc::REG_RCX as usize)
            .write(selected_route.target as libc::greg_t);
        gregs
            .add(libc::REG_RIP as usize)
            .write(selected_route.target as libc::greg_t);
    }
    true
}

fn syscall_resume(rip: u64, rcx: u64) -> u64 {
    let mut instruction = [0u8; 2];
    if crate::procmem::read_memory(rip, &mut instruction) && instruction == [0x0f, 0x05] {
        rip.wrapping_add(2)
    } else {
        rcx
    }
}

// Routing queries the real thread id; Miri does not model that syscall.
#[cfg(all(test, feature = "artifact", not(miri)))]
pub(in crate::syscall) mod artifact_tests {
    use super::{Route, SYS_SECCOMP, SYS_USER_DISPATCH, redirect};
    use core::mem::MaybeUninit;
    use libc::{_libc_fpstate, greg_t, siginfo_t, ucontext_t};

    const TARGET: u64 = 0x1234_5678_9000;
    const SERVICE: u64 = 0x1357_9bdf_89ab_cdef;
    const ORIGINAL_XMM4: [u32; 4] = [0x4444_4444; 4];
    const ORIGINAL_XMM5: [u32; 4] = [0x5555_5555; 4];
    const ART_BYPASS: [u32; 4] = [0x6969_6969, 0x6969_6969, 0xaaaa_aaaa, 0xbbbb_bbbb];
    const REFLEX_BYPASS: [u32; 4] = [0x1337_1337, 0x1337_1337, 0xaaaa_aaaa, 0xbbbb_bbbb];

    #[repr(C, align(64))]
    struct ExtendedFpState {
        legacy: _libc_fpstate,
        upper_xstate: [u8; 1024],
    }

    pub(in crate::syscall) struct Fixture {
        info: siginfo_t,
        context: ucontext_t,
        fpstate: Box<ExtendedFpState>,
        stack: Box<[u64; 8]>,
        code: Box<[u8; 32]>,
    }

    impl Fixture {
        pub(in crate::syscall) fn new(code: i32) -> Self {
            let mut info = unsafe { MaybeUninit::<siginfo_t>::zeroed().assume_init() };
            info.si_code = code;
            let mut context = unsafe { MaybeUninit::<ucontext_t>::zeroed().assume_init() };
            let mut fpstate = Box::new(ExtendedFpState {
                legacy: unsafe { MaybeUninit::<_libc_fpstate>::zeroed().assume_init() },
                upper_xstate: [0xa6; 1024],
            });
            fpstate.legacy._xmm[4].element = ORIGINAL_XMM4;
            fpstate.legacy._xmm[5].element = ORIGINAL_XMM5;
            fpstate.legacy._xmm[6].element = [0x6666_6666; 4];
            context.uc_mcontext.fpregs = &mut fpstate.legacy;
            let stack = Box::new([
                0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            ]);
            let mut instructions = Box::new([0x90; 32]);
            // RIP is already after the first SYSCALL. The following bytes
            // happen to encode another SYSCALL, and must not advance it again.
            instructions[14..18].copy_from_slice(&[0x0f, 0x05, 0x0f, 0x05]);
            let registers = &mut context.uc_mcontext.gregs;
            registers[libc::REG_RIP as usize] = unsafe { instructions.as_ptr().add(16) } as greg_t;
            registers[libc::REG_RSP as usize] = stack.as_ptr() as greg_t;
            registers[libc::REG_RAX as usize] = SERVICE as greg_t;
            registers[libc::REG_RCX as usize] = 0x1234_4321;
            registers[libc::REG_RDX as usize] = 0x2222_aaaa;
            registers[libc::REG_R8 as usize] = 0x3333_bbbb;
            registers[libc::REG_R9 as usize] = 0x4444_cccc;
            registers[libc::REG_R10 as usize] = 0x1111_dddd;
            registers[libc::REG_R11 as usize] = 0x8d7;
            registers[libc::REG_EFL as usize] = 0x202;
            registers[libc::REG_RBX as usize] = 0x1234_abcd;
            registers[libc::REG_R12 as usize] = 0x5678_efab;
            Self {
                info,
                context,
                fpstate,
                stack,
                code: instructions,
            }
        }

        fn register(&self, index: i32) -> u64 {
            self.context.uc_mcontext.gregs[index as usize] as u64
        }

        fn route_art(&mut self, target: Option<u64>) -> bool {
            unsafe {
                redirect(&self.info, &mut self.context, target, |_| {
                    panic!("ART routing must not consult Reflex")
                })
            }
        }

        /// Exercise the actual router on a trap and its later bypass; suitable
        /// for the fork-isolated dispatcher saturation fixture.
        pub(in crate::syscall) fn saturated_roundtrip(
            &mut self,
            rsp: u64,
            rip: u64,
            service: u64,
        ) -> i32 {
            self.info.si_code = SYS_USER_DISPATCH;
            let registers = &mut self.context.uc_mcontext.gregs;
            registers[libc::REG_RSP as usize] = rsp as greg_t;
            registers[libc::REG_RIP as usize] = rip as greg_t;
            registers[libc::REG_RAX as usize] = service as greg_t;
            registers[libc::REG_R11 as usize] = 0x8d7;
            registers[libc::REG_EFL as usize] = 0x202;
            self.fpstate.legacy._xmm[4].element = ORIGINAL_XMM4;
            self.fpstate.legacy._xmm[5].element = ORIGINAL_XMM5;
            let initial = self.context.uc_mcontext.gregs;

            if !unsafe { redirect(&self.info, &mut self.context, Some(TARGET), |_| None) } {
                return 13;
            }
            let mut expected = initial;
            expected[libc::REG_RAX as usize] = rip as greg_t;
            expected[libc::REG_RCX as usize] = TARGET as greg_t;
            expected[libc::REG_RIP as usize] = TARGET as greg_t;
            expected[libc::REG_EFL as usize] = 0x8d7;
            if self.context.uc_mcontext.gregs != expected
                || self.fpstate.legacy._xmm[4].element != [service as u32, 0, 0, 0]
                || self.fpstate.legacy._xmm[5].element != ORIGINAL_XMM5
            {
                return 14;
            }

            // A forked child must not inherit this thread's pending flags.
            // The child performs only the real signal path and exits without
            // allocation or locks; its parent reaps it with a deadline.
            let child = unsafe { libc::fork() };
            if child < 0 {
                return 18;
            }
            if child == 0 {
                unsafe { libc::alarm(4) };
                self.context.uc_mcontext.gregs = initial;
                self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
                self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
                self.fpstate.legacy._xmm[5].element = ART_BYPASS;
                let own_registers = self.context.uc_mcontext.gregs;
                let forwarded =
                    !unsafe { redirect(&self.info, &mut self.context, Some(TARGET), |_| None) };
                let unchanged = self.context.uc_mcontext.gregs == own_registers
                    && self.fpstate.legacy._xmm[4].element == [service as u32, 0, 0, 0]
                    && self.fpstate.legacy._xmm[5].element == [0; 4];
                unsafe { libc::_exit(if forwarded && unchanged { 42 } else { 19 }) };
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut status = 0;
            loop {
                let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                if waited == child {
                    break;
                }
                if waited < 0 {
                    if unsafe { *libc::__errno_location() } == libc::EINTR {
                        continue;
                    }
                    return 19;
                }
                if std::time::Instant::now() >= deadline {
                    unsafe {
                        libc::kill(child, libc::SIGKILL);
                        libc::waitpid(child, &mut status, 0);
                    }
                    return 19;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 42 {
                return 19;
            }

            self.context.uc_mcontext.gregs = initial;
            self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
            self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
            self.fpstate.legacy._xmm[5].element = ART_BYPASS;
            if unsafe { redirect(&self.info, &mut self.context, Some(TARGET), |_| None) } {
                return 15;
            }
            if self.context.uc_mcontext.gregs != initial {
                return 16;
            }
            if self.fpstate.legacy._xmm[4].element != [service as u32, 0, 0, 0]
                || self.fpstate.legacy._xmm[5].element != [0; 4]
                || self.fpstate.legacy._xmm[6].element != [0x6666_6666; 4]
                || self.fpstate.upper_xstate != [0xa6; 1024]
            {
                return 17;
            }
            0
        }

        pub(in crate::syscall) fn saturated_reused_site(
            &mut self,
            rsp: u64,
            rip: u64,
            service: u64,
        ) -> i32 {
            self.info.si_code = SYS_USER_DISPATCH;
            let registers = &mut self.context.uc_mcontext.gregs;
            registers[libc::REG_RSP as usize] = rsp as greg_t;
            registers[libc::REG_RIP as usize] = rip as greg_t;
            registers[libc::REG_RAX as usize] = service as greg_t;
            registers[libc::REG_R11 as usize] = 0x8d7;
            registers[libc::REG_EFL as usize] = 0x202;
            self.fpstate.legacy._xmm[5].element = ORIGINAL_XMM5;
            let first = self.context.uc_mcontext.gregs;
            if !unsafe { redirect(&self.info, &mut self.context, Some(TARGET), |_| None) } {
                return 20;
            }

            // The first callback handled the call, and the same site is now
            // used by a new call with different real flags.
            self.context.uc_mcontext.gregs = first;
            self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x246;
            self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x206;
            let second = self.context.uc_mcontext.gregs;
            if !unsafe { redirect(&self.info, &mut self.context, Some(TARGET), |_| None) } {
                return 21;
            }
            self.context.uc_mcontext.gregs = second;
            self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
            self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
            self.fpstate.legacy._xmm[5].element = ART_BYPASS;
            if unsafe { redirect(&self.info, &mut self.context, Some(TARGET), |_| None) } {
                return 22;
            }
            if self.context.uc_mcontext.gregs != second {
                return 23;
            }
            if self.fpstate.legacy._xmm[4].element != [service as u32, 0, 0, 0]
                || self.fpstate.legacy._xmm[5].element != [0; 4]
            {
                return 24;
            }
            0
        }

        fn assert_unrelated_fpstate_unchanged(&self) {
            assert_eq!(self.fpstate.legacy._xmm[6].element, [0x6666_6666; 4]);
            assert_eq!(self.fpstate.upper_xstate, [0xa6; 1024]);
        }
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    struct Marker {
        tid: u64,
        rsp: u64,
        rip: u64,
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    impl Marker {
        fn arm(fixture: &Fixture) -> Self {
            let marker = Self {
                tid: unsafe { libc::gettid() as u64 },
                rsp: fixture.register(libc::REG_RSP),
                rip: fixture.register(libc::REG_RIP),
            };
            assert!(super::super::reflex_markers::remember_marker(
                marker.tid, marker.rsp, marker.rip
            ));
            marker
        }
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    impl Drop for Marker {
        fn drop(&mut self) {
            super::super::reflex_markers::cancel(self.tid, self.rsp, self.rip);
        }
    }

    #[test]
    fn artifact_callback_uses_post_syscall_rip_and_fresh_xmm4_without_touching_arguments() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let stack = *fixture.stack;
        assert!(fixture.route_art(Some(TARGET)));

        let mut expected = initial;
        expected[libc::REG_RAX as usize] = initial[libc::REG_RIP as usize];
        expected[libc::REG_RCX as usize] = TARGET as greg_t;
        expected[libc::REG_RIP as usize] = TARGET as greg_t;
        expected[libc::REG_EFL as usize] = initial[libc::REG_R11 as usize];
        assert_eq!(fixture.context.uc_mcontext.gregs, expected);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, ORIGINAL_XMM5);
        fixture.assert_unrelated_fpstate_unchanged();
        assert_eq!(fixture.code[16..18], [0x0f, 0x05]);
    }

    #[test]
    fn artifact_bypass_forwards_service32_and_clears_only_xmm5() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        let mut expected = fixture.context.uc_mcontext.gregs;
        expected[libc::REG_RAX as usize] = 0x89ab_cdef;
        let stack = *fixture.stack;
        assert!(!fixture.route_art(Some(TARGET)));

        assert_eq!(fixture.context.uc_mcontext.gregs, expected);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0; 4]);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn artifact_sse_edits_publish_only_the_sse_xsave_header_bit() {
        for bypass in [false, true] {
            let mut fixture = Fixture::new(SYS_USER_DISPATCH);
            let bytes = (&mut fixture.fpstate.legacy as *mut _libc_fpstate).cast::<u8>();
            unsafe {
                bytes.add(464).cast::<u32>().write_unaligned(0x4650_5853);
                bytes.add(468).cast::<u32>().write_unaligned(836);
                bytes.add(480).cast::<u32>().write_unaligned(832);
            }
            fixture.fpstate.upper_xstate[..8].copy_from_slice(&4u64.to_ne_bytes());
            if bypass {
                fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
            }
            assert_eq!(fixture.route_art(Some(TARGET)), !bypass);
            assert_eq!(&fixture.fpstate.upper_xstate[..8], &6u64.to_ne_bytes());
            assert_eq!(&fixture.fpstate.upper_xstate[8..], &[0xa6; 1016]);
            assert_eq!(
                fixture.fpstate.legacy._xmm[4].element,
                [0x89ab_cdef, 0, 0, 0]
            );
        }
    }

    #[test]
    fn artifact_sse_rejects_malformed_metadata_before_touching_a_guarded_extension() {
        struct Mapping(*mut core::ffi::c_void);
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, 8192);
                }
            }
        }
        assert_eq!(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }, 4096);
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let mapping = Mapping(raw);
        let bytes = raw.cast::<u8>();
        assert_eq!(
            unsafe { libc::mprotect(bytes.add(4096).cast(), 4096, libc::PROT_NONE) },
            0
        );
        let prefix = unsafe { bytes.add(4096 - 512) };
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.context.uc_mcontext.fpregs = prefix.cast();
        for (extent, size) in [
            (576u32, 576u32),
            (580, 575),
            (580, 577),
            (u32::MAX, u32::MAX),
        ] {
            unsafe {
                core::ptr::write_bytes(prefix, 0, 512);
                prefix.add(464).cast::<u32>().write_unaligned(0x4650_5853);
                prefix.add(468).cast::<u32>().write_unaligned(extent);
                prefix.add(480).cast::<u32>().write_unaligned(size);
            }
            let initial = fixture.context.uc_mcontext.gregs;
            let before = unsafe { core::slice::from_raw_parts(prefix, 512) }.to_vec();
            assert!(!fixture.route_art(Some(TARGET)));
            assert_eq!(fixture.context.uc_mcontext.gregs, initial);
            assert_eq!(unsafe { core::slice::from_raw_parts(prefix, 512) }, before);
        }
        // Without XSAVE magic, the exact same 512-byte frame is valid legacy
        // state; its protected successor must never be accessed.
        unsafe { prefix.add(464).cast::<u32>().write_unaligned(0) };
        assert!(fixture.route_art(Some(TARGET)));
        assert_eq!(
            unsafe { (*fixture.context.uc_mcontext.fpregs)._xmm[4].element },
            [0x89ab_cdef, 0, 0, 0]
        );
        drop(mapping);
    }

    #[test]
    fn artifact_does_not_accept_reflex_bypass_magic() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = REFLEX_BYPASS;
        let rip = fixture.register(libc::REG_RIP);
        assert!(fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.register(libc::REG_RAX), rip);
        assert_eq!(fixture.register(libc::REG_RIP), TARGET);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, REFLEX_BYPASS);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn artifact_foreign_or_unregistered_call_forwards_unchanged() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        let initial = fixture.context.uc_mcontext.gregs;
        let stack = *fixture.stack;
        assert!(!fixture.route_art(None));
        assert_eq!(fixture.context.uc_mcontext.gregs, initial);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(fixture.fpstate.legacy._xmm[4].element, ORIGINAL_XMM4);
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, ART_BYPASS);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn artifact_does_not_claim_seccomp_events() {
        for xmm5 in [ART_BYPASS, REFLEX_BYPASS] {
            let mut fixture = Fixture::new(SYS_SECCOMP);
            fixture.fpstate.legacy._xmm[5].element = xmm5;
            let initial = fixture.context.uc_mcontext.gregs;
            assert!(!fixture.route_art(Some(TARGET)));
            assert_eq!(fixture.context.uc_mcontext.gregs, initial);
            assert_eq!(fixture.fpstate.legacy._xmm[4].element, ORIGINAL_XMM4);
            assert_eq!(fixture.fpstate.legacy._xmm[5].element, xmm5);
            fixture.assert_unrelated_fpstate_unchanged();
        }
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    #[test]
    fn artifact_seccomp_preserves_pending_marker_for_later_bypass() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let stack = *fixture.stack;
        let _marker = Marker::arm(&fixture);
        assert!(fixture.route_art(Some(TARGET)));

        fixture.info.si_code = SYS_SECCOMP;
        fixture.context.uc_mcontext.gregs = initial;
        fixture.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
        fixture.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
        fixture.fpstate.legacy._xmm[4].element = [0xaaaa_aaaa; 4];
        fixture.fpstate.legacy._xmm[5].element = REFLEX_BYPASS;
        let seccomp_registers = fixture.context.uc_mcontext.gregs;
        assert!(!fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.context.uc_mcontext.gregs, seccomp_registers);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(fixture.fpstate.legacy._xmm[4].element, [0xaaaa_aaaa; 4]);
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, REFLEX_BYPASS);
        fixture.assert_unrelated_fpstate_unchanged();

        fixture.info.si_code = SYS_USER_DISPATCH;
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        assert!(!fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.register(libc::REG_R11), 0x8d7);
        assert_eq!(fixture.register(libc::REG_EFL), 0x202);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0; 4]);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    #[test]
    fn artifact_repeated_site_routes_again_instead_of_replaying_stale_marker() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let _marker = Marker::arm(&fixture);
        assert!(fixture.route_art(Some(TARGET)));

        fixture.context.uc_mcontext.gregs = initial;
        fixture.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x246;
        fixture.fpstate.legacy._xmm[4].element = [0xaaaa_aaaa; 4];
        fixture.fpstate.legacy._xmm[5].element = [0xbbbb_bbbb; 4];
        assert!(fixture.route_art(Some(TARGET)));
        assert_eq!(
            fixture.register(libc::REG_RAX),
            initial[libc::REG_RIP as usize] as u64
        );
        assert_eq!(fixture.register(libc::REG_RIP), TARGET);
        assert_eq!(fixture.register(libc::REG_EFL), 0x246);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0xbbbb_bbbb; 4]);
        fixture.assert_unrelated_fpstate_unchanged();

        fixture.context.uc_mcontext.gregs = initial;
        fixture.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
        fixture.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
        fixture.fpstate.legacy._xmm[4].element = [0xcccc_cccc; 4];
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        assert!(!fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.register(libc::REG_R11), 0x246);
        assert_eq!(fixture.register(libc::REG_EFL), 0x202);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0; 4]);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    #[test]
    fn artifact_bypass_retires_bridge_marker_and_restores_saved_flags_not_xmm_junk() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let marker = Marker::arm(&fixture);
        assert!(fixture.route_art(Some(TARGET)));

        fixture.context.uc_mcontext.gregs = initial;
        fixture.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
        fixture.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
        fixture.fpstate.legacy._xmm[4].element = [0xaaaa_aaaa; 4];
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        assert!(!fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.register(libc::REG_R11), 0x8d7);
        assert_eq!(fixture.register(libc::REG_EFL), 0x202);
        assert_eq!(fixture.register(libc::REG_RAX), u64::from(SERVICE as u32));
        assert_eq!(
            fixture.register(libc::REG_RIP),
            initial[libc::REG_RIP as usize] as u64
        );
        assert_eq!(
            fixture.register(libc::REG_RSP),
            initial[libc::REG_RSP as usize] as u64
        );
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0; 4]);
        fixture.assert_unrelated_fpstate_unchanged();
        assert!(
            super::super::reflex_markers::consume(
                marker.tid, marker.rsp, marker.rip, [0; 16], [0; 16], 0, 0,
            )
            .is_none()
        );
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    #[test]
    fn artifact_first_hop_bypass_cancels_unneeded_route_marker() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        let mut expected = fixture.context.uc_mcontext.gregs;
        expected[libc::REG_RAX as usize] = 0x89ab_cdef;
        let marker = Marker::arm(&fixture);
        assert!(!fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.context.uc_mcontext.gregs, expected);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0; 4]);
        assert!(
            super::super::reflex_markers::consume(
                marker.tid, marker.rsp, marker.rip, [0; 16], [0; 16], 0, 0,
            )
            .is_none()
        );
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    #[test]
    fn artifact_new_site_retires_completed_same_depth_marker() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let marker = Marker::arm(&fixture);
        assert!(fixture.route_art(Some(TARGET)));
        fixture.context.uc_mcontext.gregs = initial;
        fixture.context.uc_mcontext.gregs[libc::REG_RIP as usize] += 4;
        let second_rip = fixture.register(libc::REG_RIP);
        assert!(fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.register(libc::REG_RAX), second_rip);
        assert_eq!(fixture.register(libc::REG_RIP), TARGET);
        assert!(
            super::super::reflex_markers::consume(
                marker.tid, marker.rsp, marker.rip, [0; 16], [0; 16], 0, 0,
            )
            .is_none()
        );
    }

    #[cfg(all(feature = "kuser", feature = "reflex"))]
    #[test]
    fn artifact_feature_preserves_reflex_bridge_route_and_replay_saved_state() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let _marker = Marker::arm(&fixture);
        assert!(unsafe {
            redirect(&fixture.info, &mut fixture.context, None, |_| {
                Some(Route {
                    target: TARGET,
                    rax_is_resume: true,
                })
            })
        });
        assert_eq!(
            fixture.register(libc::REG_RAX),
            initial[libc::REG_RIP as usize] as u64 + 2
        );
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0x4444_4444, 0x4444_4444, 0x4444_4444]
        );

        fixture.context.uc_mcontext.gregs = initial;
        fixture.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
        fixture.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
        fixture.fpstate.legacy._xmm[4].element = [0xaaaa_aaaa; 4];
        fixture.fpstate.legacy._xmm[5].element = [0xbbbb_bbbb; 4];
        assert!(!fixture.route_art(None));
        assert_eq!(fixture.register(libc::REG_R11), 0x8d7);
        assert_eq!(fixture.register(libc::REG_EFL), 0x202);
        assert_eq!(fixture.fpstate.legacy._xmm[4].element, ORIGINAL_XMM4);
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, ORIGINAL_XMM5);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn syscall_resume_handles_unreadable_and_page_boundary_rip_without_faulting() {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(page_size, 4096);
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                page_size * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        struct Mapping(*mut core::ffi::c_void, usize);
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, self.1);
                }
            }
        }
        let _guard = Mapping(raw, page_size * 2);
        let bytes = raw.cast::<u8>();
        assert_eq!(
            unsafe { libc::mprotect(bytes.add(page_size).cast(), page_size, libc::PROT_NONE) },
            0
        );
        unsafe {
            bytes.add(page_size - 2).write(0x0f);
            bytes.add(page_size - 1).write(0x05);
        }
        let at_end = bytes as u64 + page_size as u64 - 2;
        assert_eq!(super::syscall_resume(at_end, 0xdead), at_end + 2);
        let straddling = bytes as u64 + page_size as u64 - 1;
        assert_eq!(super::syscall_resume(straddling, 0xbeef), 0xbeef);
        assert_eq!(super::syscall_resume(0x1000, 0xcafe), 0xcafe);
    }
}
