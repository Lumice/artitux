//! ARTIFACT's PID-first CPUID handshake and syscall resume contract.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::reflex::SyscallRoute;

pub const SYSCALL_BYPASS_MAGIC: u64 = 0x6969_6969_6969_6969;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuidAction {
    Native,
    /// Ordinary CPUID query in a PID-registered ART session.
    Query,
    Zero,
    /// Write only RAX=1; all other incoming registers remain unchanged.
    Ready,
}

#[derive(Debug)]
pub struct State {
    target_pid: AtomicU64,
    callback: AtomicU64,
    ready_pending: AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            target_pid: AtomicU64::new(0),
            callback: AtomicU64::new(0),
            ready_pending: AtomicBool::new(false),
        }
    }

    /// `provider_ready` must describe the real process-private live provider.
    /// Registering a PID or callback alone never asserts provider readiness.
    pub fn cpuid(&self, leaf: u32, rcx: u64, rdx: u64, provider_ready: bool) -> CpuidAction {
        match leaf {
            0x1337 => {
                if self
                    .target_pid
                    .compare_exchange(0, rdx, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.ready_pending.store(true, Ordering::Release);
                }
            }
            0x336933 if self.has_target_process() && rcx != 0 => {
                let _ = self
                    .callback
                    .compare_exchange(0, rcx, Ordering::AcqRel, Ordering::Acquire);
            }
            0x336967 if self.has_target_process() => return CpuidAction::Zero,
            0x1338
                if self.has_target_process()
                    && provider_ready
                    && self.ready_pending.swap(false, Ordering::AcqRel) =>
            {
                return CpuidAction::Ready;
            }
            _ => {}
        }
        if self.has_target_process() && !matches!(leaf, 0x1337 | 0x336933 | 0x1338 | 0x336967) {
            CpuidAction::Query
        } else {
            CpuidAction::Native
        }
    }

    pub fn has_target_process(&self) -> bool {
        self.target_pid.load(Ordering::Acquire) != 0
    }

    pub fn route_syscall(&self) -> Option<SyscallRoute> {
        if !self.has_target_process() {
            return None;
        }
        let target = self.callback.load(Ordering::Acquire);
        (target != 0).then_some(SyscallRoute {
            target,
            rax_is_resume: true,
        })
    }

    /// The child has no provider worker and must register its own session.
    pub fn after_fork(&self) {
        self.callback.store(0, Ordering::Release);
        self.target_pid.store(0, Ordering::Release);
        self.ready_pending.store(false, Ordering::Release);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CpuidAction, State};

    #[test]
    fn pid_first_registration_routes_only_after_a_nonzero_callback() {
        let state = State::new();
        assert!(state.route_syscall().is_none());
        assert_eq!(
            state.cpuid(0x1337, 0xdead, 0x174, false),
            CpuidAction::Native
        );
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x336933, 0, 0, false), CpuidAction::Native);
        assert!(state.route_syscall().is_none());
        assert_eq!(
            state.cpuid(0x336933, 0x6ffffa761000, 0, false),
            CpuidAction::Native
        );
        let route = state.route_syscall().expect("registered ART callback");
        assert_eq!(route.target, 0x6ffffa761000);
        assert!(route.rax_is_resume);
        state.cpuid(0x1337, 0, 0x999, true);
        state.cpuid(0x336933, 0x6ffffa762000, 0, true);
        assert_eq!(state.route_syscall().unwrap().target, 0x6ffffa761000);
    }

    #[test]
    fn readiness_waits_for_the_real_provider_and_is_consumed_once() {
        let state = State::new();
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        state.cpuid(0x336933, 0x6ffffa761000, 0, false);
        assert_eq!(state.cpuid(0x1338, 0, 0, false), CpuidAction::Native);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, true);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
    }

    #[test]
    fn optional_control_is_zero_only_for_the_registered_process() {
        let state = State::new();
        assert_eq!(state.cpuid(0x336967, 0, 0, false), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        assert_eq!(state.cpuid(0x336967, 0, 0, false), CpuidAction::Zero);
    }

    #[test]
    fn cpu_profile_requires_pid_registration_and_ends_at_fork() {
        let state = State::new();
        assert_eq!(state.cpuid(1, 0, 0, false), CpuidAction::Native);
        state.cpuid(0x336933, 0x1234, 0, false);
        assert_eq!(state.cpuid(1, 0, 0, false), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        assert_eq!(state.cpuid(1, 0, 0, false), CpuidAction::Query);
        assert_eq!(state.cpuid(0x1338, 0, 0, false), CpuidAction::Native);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
        assert_eq!(state.cpuid(1, 0, 0, true), CpuidAction::Query);
        assert_eq!(state.cpuid(0x336933, 0, 0, false), CpuidAction::Native);
        state.after_fork();
        assert_eq!(state.cpuid(1, 0, 0, true), CpuidAction::Native);
    }
}

#[cfg(test)]
mod fork_tests {
    use super::{CpuidAction, State};

    #[test]
    fn fork_child_cannot_route_or_claim_the_parent_provider_readiness() {
        let state = State::new();
        state.cpuid(0x1337, 0, 0x174, false);
        state.cpuid(0x336933, 0x6ffffa761000, 0, false);
        assert!(state.route_syscall().is_some());
        state.after_fork();
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x180, true);
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
    }
}
