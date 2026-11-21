//! Syscall interception: the KUSER dispatcher bridge (`kuser_dispatch`) that
//! classifies calls arriving through Wine's KUSER dispatcher slot, the SIGSYS
//! router (`sigsys_router`) that routes Artifact SYS_USER_DISPATCH calls,
//! `int2e` emulation for anti-tamper code issuing `int 2e`, and the `mmap`
//! observer (`pe_stub_layout`) used by the Artifact loader and CPUID mapping
//! tracker.

#[cfg(all(feature = "kuser", feature = "cpuid"))]
use libc::ucontext_t;
#[cfg(feature = "artifact")]
mod artifact_flags;
#[cfg(all(feature = "kuser", feature = "cpuid"))]
mod int2e;
#[cfg(feature = "artifact")]
mod kuser_dispatch;
#[cfg(feature = "artifact")]
mod pe_stub_layout;
mod sigsys_router;

#[cfg(all(feature = "kuser", feature = "cpuid"))]
pub(crate) unsafe fn skip_int2e_fault(context: *mut ucontext_t) -> bool {
    unsafe { int2e::skip_int2e_fault(context) }
}

#[cfg(feature = "artifact")]
pub(crate) fn install_wine_syscall_dispatcher_bridge() -> bool {
    kuser_dispatch::install()
}
