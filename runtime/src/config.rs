//! Startup-only CPU profile selectors, with no environment reads in traps.
//! `ARTITUX_LEGACY_PROFILE` is a separate process-wide flag, read once at
//! startup, that forces the legacy CPU/KUSER presentation for the whole
//! process rather than letting `cpuid.rs`'s per-caller Reflex-image
//! detection decide it. Kept in its own tiny module (rather than inline in
//! `cpuid.rs`) because it's read from an `.init_array` constructor before
//! most other runtime state exists.
#[cfg(feature = "cpuid")]
use core::ffi::CStr;
#[cfg(feature = "cpuid")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "cpuid")]
static LEGACY_PROFILE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "artifact")]
static RESOLVER_BRIDGE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "artifact")]
static ARTIFACT_NATIVE_STUBS: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "artifact")]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn artifact_native_stubs() -> bool {
    ARTIFACT_NATIVE_STUBS.load(Ordering::Acquire)
}

#[cfg(feature = "artifact")]
pub(crate) fn resolver_bridge_enabled() -> bool {
    RESOLVER_BRIDGE.load(Ordering::Acquire)
}

#[cfg(feature = "cpuid")]
pub(crate) fn legacy_profile_forced() -> bool {
    LEGACY_PROFILE.load(Ordering::Acquire)
}

#[cfg(feature = "cpuid")]
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
    #[cfg(feature = "cpuid")]
    LEGACY_PROFILE.store(env_flag_set(c"ARTITUX_LEGACY_PROFILE"), Ordering::Release);
    #[cfg(feature = "artifact")]
    {
        // Artifact builds need both; the launcher sets only LD_PRELOAD.
        // "0" remains an explicit opt-out for diagnosis.
        RESOLVER_BRIDGE.store(!env_flag_off(c"ARTITUX_RESOLVER_BRIDGE"), Ordering::Release);
        ARTIFACT_NATIVE_STUBS.store(
            !env_flag_off(c"ARTITUX_ARTIFACT_NATIVE_STUBS"),
            Ordering::Release,
        );
    }
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
