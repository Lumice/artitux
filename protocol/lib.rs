//! Artitux's safe protocol core: the pure, `no_std`, unsafe-forbidden
//! decision logic for the Artifact compatibility protocol, with no
//! knowledge of libc, signals, or process memory. `runtime/` is the unsafe
//! FFI/signal-handling shell that drives this crate directly (Artifact CPUID
//! profiles, KUSER writes, environment/gamescope string parsing, and
//! faketime offset math).
#![forbid(unsafe_code)]
#![no_std]

pub mod artifact;
pub mod artifact_cpu;
pub mod artifact_profile;
pub mod cpuid;
pub mod debug;
pub mod environment;
pub mod faketime;
pub mod gamescope;
pub mod kuser;
