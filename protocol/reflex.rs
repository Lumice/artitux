//! The Reflex CPUID control protocol and syscall routing state machine —
//! the safe core `runtime/src/reflex.rs` drives through the [`Host`] trait,
//! and that `runtime/src/syscall/sigsys_router.rs` calls into via
//! [`State::route_syscall`]. Titles can use resume-target or dual-dispatch
//! routing, with CR3 or DR3/DR7 identity.
mod control;
mod state;

pub use control::{
    ARM_TARGET_CR3, CLIENT_SESSION_MARKER, REGISTER_ATTRIBUTES_HANDLER,
    REGISTER_ATTRIBUTES_SYSCALL_ID, REGISTER_RESUME_HANDLER, REGISTER_SYSTEM_SYSCALL_ID,
    REGISTER_TARGET_PID, SET_TIME, SYSCALL_BYPASS_MAGIC,
};
pub use state::{Action, Host, IdentityScope, KuserRecipe, Routing, State, SyscallRoute};
