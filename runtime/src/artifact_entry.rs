//! Native C entry used to exercise ART initialization from ordinary Wine PE
//! context. It does not install another signal or syscall bridge.

/// The caller must be an ordinary Wine PE thread with an initialized TEB,
/// not a signal handler or a native worker. Returns one only after the real
/// private provider and dispatcher initialization succeeds, or negative errno
/// on failure so diagnostic callers retain the actual failure category.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn artitux_artifact_prepare() -> libc::c_int {
    let _errno = crate::errno::Errno::save();
    // This is an ordinary Wine PE preparation boundary. The observer may have
    // seen Wine mappings before any CPUID query, so mark the Wine context here
    // before the resolver registration asks for the TEB dispatch guard.
    crate::artifact::mark_detected();
    if !crate::resolver::register_unwind_from_prepare() {
        return -libc::EOPNOTSUPP;
    }
    match crate::artifact::prepare() {
        Ok(()) => 1,
        Err(error) => {
            use crate::artifact::InitializeError;
            use crate::artifact_kuser::PrepareError;
            let code = match error {
                InitializeError::UnsupportedGsBaseAccess => libc::EOPNOTSUPP,
                InitializeError::NotWineThread => libc::EINVAL,
                InitializeError::Busy => libc::EBUSY,
                InitializeError::Dispatcher => libc::EIO,
                InitializeError::Provider(error) => match error {
                    PrepareError::System(code)
                    | PrepareError::Worker(code)
                    | PrepareError::Rollback(code) => code,
                    PrepareError::UnsupportedPageSize => libc::EOPNOTSUPP,
                    PrepareError::Busy => libc::EBUSY,
                    PrepareError::IncoherentClock => libc::EAGAIN,
                    PrepareError::WorkerTimeout => libc::ETIMEDOUT,
                    PrepareError::InvalidWineMapping | PrepareError::InvalidDispatchMapping => {
                        libc::EINVAL
                    }
                },
            };
            -code
        }
    }
}

fn may_repair_after_return(result: u64, owner: bool, callback: bool) -> bool {
    result as u32 != 0 && owner && callback
}

/// Called only by the native wrapper's normal-return path after loader cleanup.
/// Its count is diagnostic; the wrapper retains the actual full DLL result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn artitux_artifact_after_return(result: u64) -> libc::c_int {
    let _errno = crate::errno::Errno::save();
    if result as u32 == 0 {
        return 0;
    }
    let Some(_dispatch) = (unsafe { crate::artifact::wine_dispatch_guard() }) else {
        return 0;
    };
    if !may_repair_after_return(
        result,
        crate::artifact::active(),
        crate::artifact::syscall_target().is_some(),
    ) {
        return 0;
    }
    let repaired = crate::syscall::repair_completed_artifact_exports();
    #[cfg(feature = "debug")]
    unsafe {
        crate::debug::debug_log_dec(
            c"artifact completed-client Wine data exports repaired=".as_ptr(),
            repaired as u64,
        )
    };
    repaired as libc::c_int
}

#[cfg(test)]
mod after_return_tests {
    #[test]
    fn normal_return_maintenance_requires_true_bool_and_owned_callback() {
        for (result, owner, callback, expected) in [
            (0, true, true, false),
            (0x1_0000_0000, true, true, false),
            (1, false, true, false),
            (1, true, false, false),
            (1, true, true, true),
            (0xabcd_0000_0001, true, true, true),
        ] {
            assert_eq!(
                super::may_repair_after_return(result, owner, callback),
                expected
            );
        }
    }
}
