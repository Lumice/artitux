//! Startup-only runtime option selectors, with no environment reads in traps.
#[cfg(feature = "artifact")]
use core::ffi::CStr;
#[cfg(feature = "artifact")]
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(feature = "artifact")]
static RESOLVER_BRIDGE: AtomicBool = AtomicBool::new(false);

/// `ARTITUX_VBS20`: 1 forces the VBS 2.0 hypervisor's CPU and KUSER view,
/// 0 forces VBS 1.9; unset (or anything else) selects automatically.
#[cfg(feature = "artifact")]
static VBS20: AtomicU8 = AtomicU8::new(VBS20_AUTO);
#[cfg(feature = "artifact")]
const VBS20_AUTO: u8 = 0;
#[cfg(feature = "artifact")]
const VBS20_ON: u8 = 1;
#[cfg(feature = "artifact")]
const VBS20_OFF: u8 = 2;

/// Set when this process's `artifact.dll` contains the VBS 2.0 marker.
#[cfg(feature = "artifact")]
static VBS20_MARKER: AtomicBool = AtomicBool::new(false);

/// `ARTITUX_SYSCALL_LEAK_TRAP=0` turns off the seccomp trap for Windows
/// syscalls that bypass Wine's syscall user dispatch (diagnosis only).
#[cfg(feature = "artifact")]
static SYSCALL_LEAK_TRAP: AtomicBool = AtomicBool::new(true);

#[cfg(feature = "artifact")]
pub(crate) fn syscall_leak_trap_enabled() -> bool {
    SYSCALL_LEAK_TRAP.load(Ordering::Acquire)
}

/// The VBS generation for the registered Artifact release: the override,
/// else what its `artifact.dll` was built for (see
/// `artifact_profile::select_generation`).
#[cfg(feature = "artifact")]
pub(crate) fn artifact_generation() -> artitux::artifact_profile::Generation {
    let forced = match VBS20.load(Ordering::Acquire) {
        VBS20_ON => Some(true),
        VBS20_OFF => Some(false),
        _ => None,
    };
    artitux::artifact_profile::select_generation(forced, VBS20_MARKER.load(Ordering::Acquire))
}

/// Record whether this process's `artifact.dll` contains the VBS 2.0
/// marker. Set once, before Artifact's DllMain runs.
#[cfg(feature = "artifact")]
pub(crate) fn set_artifact_vbs20_marker(found: bool) {
    VBS20_MARKER.store(found, Ordering::Release);
}

#[cfg(feature = "artifact")]
pub(crate) fn resolver_bridge_enabled() -> bool {
    RESOLVER_BRIDGE.load(Ordering::Acquire)
}

#[cfg(feature = "artifact")]
fn env_flag_set(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"1"
}

#[cfg(feature = "artifact")]
fn env_flag_off(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"0"
}

unsafe extern "C" fn initialize() {
    #[cfg(feature = "artifact")]
    {
        // Artifact builds need the resolver bridge; the launcher sets only
        // LD_PRELOAD. "0" remains an explicit opt-out for diagnosis.
        RESOLVER_BRIDGE.store(!env_flag_off(c"ARTITUX_RESOLVER_BRIDGE"), Ordering::Release);
        VBS20.store(
            if env_flag_set(c"ARTITUX_VBS20") {
                VBS20_ON
            } else if env_flag_off(c"ARTITUX_VBS20") {
                VBS20_OFF
            } else {
                VBS20_AUTO
            },
            Ordering::Release,
        );
        SYSCALL_LEAK_TRAP.store(
            !env_flag_off(c"ARTITUX_SYSCALL_LEAK_TRAP"),
            Ordering::Release,
        );
    }
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
