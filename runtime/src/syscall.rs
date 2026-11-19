//! Syscall interception includes the KUSER dispatcher bridge
//! (`kuser_dispatch`) that classifies calls arriving through Wine's KUSER
//! dispatcher slot, the SIGSYS router (`sigsys_router`) that decides
//! Wine-vs-Reflex for a trapped syscall, two fixups (`int2e`,
//! `pe_stub_layout`) for anti-tamper code that expects Windows' own syscall
//! gate and thunk bytes, and one narrow Wine window-list compatibility fix
//! (`win32u_zero_list`). This file is a
//! thin facade: it declares the submodules and re-exports the few entry
//! points other files in `runtime/` call by name.

#[cfg(all(feature = "kuser", feature = "cpuid"))]
use libc::ucontext_t;
#[cfg(feature = "artifact")]
mod artifact_flags;

#[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
mod diagnostics;
#[cfg(all(feature = "kuser", feature = "cpuid"))]
mod int2e;
#[cfg(all(feature = "kuser", feature = "reflex"))]
mod kuser_dispatch;
#[cfg(all(feature = "kuser", feature = "reflex"))]
mod mem;
#[cfg(all(feature = "kuser", feature = "reflex"))]
mod pe_export;
#[cfg(all(feature = "kuser", feature = "environment"))]
mod pe_stub_layout;
#[cfg(all(feature = "kuser", feature = "reflex"))]
mod reflex_markers;
mod sigsys_router;
#[cfg(all(feature = "kuser", feature = "reflex"))]
mod unixlib_repair;
#[cfg(all(feature = "kuser", feature = "reflex"))]
mod win32u_zero_list;

#[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
pub(crate) fn trace_null_fault(address: usize, rip: u64, tid: u64) {
    diagnostics::dump_on_null_fault(address, rip, tid);
}

#[cfg(all(feature = "kuser", feature = "cpuid"))]
pub(crate) unsafe fn skip_int2e_fault(context: *mut ucontext_t) -> bool {
    unsafe { int2e::skip_int2e_fault(context) }
}

#[cfg(all(feature = "kuser", feature = "reflex", feature = "cpuid"))]
pub(crate) fn register_reflex_dispatch_handler(handler: u64) {
    kuser_dispatch::register_reflex_dispatch_handler(handler);
}

#[cfg(all(feature = "kuser", feature = "reflex"))]
pub(crate) fn install_wine_syscall_dispatcher_bridge() -> bool {
    kuser_dispatch::install()
}

/// Ordinary-context maintenance after a successfully returned Artifact client.
#[cfg(feature = "artifact")]
pub(crate) fn repair_completed_artifact_exports() -> usize {
    unixlib_repair::repair_completed_artifact_exports()
}
