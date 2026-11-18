# Architecture

A map of how this codebase is put together, for anyone starting fresh. See
[`docs/protocol/`](protocol/README.md) for the *protocol* this code
implements (what Reflex/Denuvo expect, per-title differences); this document
is about the *code*.

## The three crates

| Crate | Directory | What it is |
| --- | --- | --- |
| `artitux-rust` (`artitux`) | `protocol/` | The safe core: `no_std`, `#![forbid(unsafe_code)]`, unit-tested. Pure decision logic — CPUID reply tables, KUSER patch recipes, the Reflex registration/routing state machine, string parsing for environment/gamescope detection. No libc, no signals, no process memory. |
| `artitux-runtime` | `runtime/` | The unsafe shell. Drives `protocol/`'s logic through the `Host` trait pattern (see `protocol/reflex/state.rs`) and calls its pure functions directly elsewhere. Owns every signal handler, every libc interposition, every `mprotect`/`process_vm_readv` call. Feature-gated per module (see `runtime/Cargo.toml`) so CI can build and lint every supported subset. |
| `xtask` | `xtask/` | The build tool. Links `artitux-runtime` into `Artitux.so` with an explicit export map and linker hardening, then verifies the result (exported symbols, ELF properties, `.init_array` constructor order). This verification is the actual safety net for structural changes: a bad rename or a dropped `#[no_mangle]` fails the build, not just a review. |

Why the split: code that never touches a raw pointer or a syscall can be
tested with plain `cargo test`, reasoned about without thinking about signal
reentrancy, and kept `#![forbid(unsafe_code)]` to guarantee it stays that
way. Everything that genuinely needs `unsafe` — FFI, signal handlers, raw
memory access — lives in `runtime/` instead, as thin as each module allows.
`protocol/` and `runtime/` used to both be named things like `src/cpuid.rs`
and `runtime/src/cpuid.rs`, which made it easy to open the wrong one; they're
`protocol/` and `runtime/` now specifically so that's no longer ambiguous.

## `runtime/`'s modules

Each `.init_array`-registered module owns one concern and runs its own setup
constructor at process start (see the `link_section = ".init_array.NNNNN"`
statics — the number fixes their relative order, verified by `xtask`):

- **`debug.rs`** — runs first (`.init_array.00102`); `ARTITUX_DEBUG`/`ARTITUX_LOG`
  handling; every other module's logging goes through its C ABI.
- **`gamescope.rs`** — detects a Gamescope session (`.init_array.00103`) and
  keeps Artitux's `LD_PRELOAD` entry alive across Gamescope's re-exec.
- **`environment.rs`** — decides whether this process is the game's own
  `.exe`, forces native DLL overrides if so, and triggers `registry.rs`.
- **`config.rs`** — startup-only environment flags (`ARTITUX_LEGACY_PROFILE`,
  `ARTITUX_RESOLVER_BRIDGE`, `ARTITUX_ARTIFACT_NATIVE_STUBS`).
- **`faketime.rs`** — the `gettimeofday` clock offset Reflex's `SET_TIME`
  control leaf sets.
- **`hooks.rs`** — signal interposition that keeps Artitux's `SIGSEGV`/`SIGSYS`
  handlers ahead of Wine's own, plus the opt-in indexed `win32u` duplicate-`free`
  guard in `hooks/pending_frees.rs`.
- **`kuser.rs`** — owns the live `KUSER_SHARED_DATA` page: applies patch
  recipes from `protocol/kuser.rs`, and (legacy, being phased out — see
  `docs/protocol/topspin-investigation.md`) the `ARTITUX_SYSCALL_HACK` flag.
- **`cpuid.rs`** — the SIGSEGV/CPUID trap handler: per-caller Reflex-image
  detection, native CPUID pass-through, reply selection via `protocol/cpuid.rs`
  and `protocol/artifact*.rs`.
- **`reflex.rs`** — the C ABI into `protocol/reflex/state.rs::State`, and
  `RuntimeHost`, the seam where the safe core's decisions become real
  `mprotect`/logging/presentation side effects.
- **`artifact.rs` / `artifact_entry.rs` / `artifact_kuser.rs` /
  `artifact_loader.rs` / `peb_heaps.rs` / `resolver.rs` / `resolver.S`** —
  preload-only Artifact runtime: capabilities detection, KUSER private clock
  worker, loader/PEB heap adoption, and native unwind/resolver bridge.
- **`syscall/`** — the SIGSYS boundary (`sigsys_router.rs`, `kuser_dispatch.rs`,
  `reflex_markers.rs`, `int2e.rs`, `pe_stub_layout.rs`, `unixlib_repair.rs`,
  `artifact_flags.rs`, `mem.rs`); see below.
- **`registry.rs`** — writes a `HwProfileGuid` key into the Wine prefix's
  registry on first run.

## The syscall boundary (`runtime/src/syscall/`)

This is the part `docs/protocol/syscall-routing.md` describes in protocol
terms; in source it's three independent stages plus two unrelated fixups:

1. **`kuser_dispatch.rs`** — installs Artitux's handler in Wine's KUSER
   dispatcher slot (a hand-written naked-asm trampoline, `dispatcher_bridge`,
   with a private stack per Windows thread id) and classifies every call
   that arrives through it: is this evidenced as Reflex's own copied syscall
   stub (found by scanning the main PE image's IAT), or an ordinary Wine
   call? That rule is `should_replay_raw`, a small pure function — the one
   piece of this classification with no pointers or I/O, and the one
   `docs/protocol/syscall-routing.md` invariant 2 and the unit tests pin
   down directly.
2. **`reflex_markers.rs`** — the Route/Replay marker lifecycle connecting
   stage 1's decision to stage 3's trap: a marker armed when
   `kuser_dispatch` replays a call raw is consumed when the resulting
   syscall traps, and consumed again when Reflex bounces it back to Wine.
   Also owns `is_registered_target_process`, a separate, simpler signal for
   direct syscalls from a process that has completed Reflex's own
   registration handshake.
3. **`sigsys_router.rs`** — the actual `SIGSYS` signal handler
   (`syscallhook`). Given a trapped syscall, decides Wine-forward vs.
   `protocol/reflex/state.rs::State::route_syscall` vs. bypass-replay, and
   restores caller-visible state (XMM4/5, R11, EFLAGS) exactly once per
   marker. Always compiled, independent of the `kuser`/`reflex` features —
   without them every call simply forwards to Wine, which is correct.
4. **`int2e.rs`** — emulates Windows' `int 2e` syscall gate, which Linux has
   no equivalent trap for: resumes at the thunk's own direct-syscall path
   when possible, or a private executable trampoline, without modifying the
   game's own code bytes (anti-tamper code hashes them).
5. **`pe_stub_layout.rs`** — rewrites the tail bytes of syscall thunks in
   whole-file/mmap'd reads of system DLLs to Windows' real layout, so
   anti-tamper code that pattern-matches a clean copy of `ntdll.dll`
   resolves the right address instead of Wine's own (Wine-build-specific)
   tail.
6. **`unixlib_repair.rs`** — fixes an unrelated Reflex side effect: Reflex's
   "hook every export" approach breaks two Wine-only data exports it
   mistakes for code.
7. **`mem.rs`** — the `process_vm_readv`/`writev` helpers `kuser_dispatch.rs`
   and `unixlib_repair.rs` share, so a bad address becomes a failed syscall
   rather than a segfault.

`int2e.rs` and `pe_stub_layout.rs` are self-contained fixes for specific
Windows/Wine divergences unrelated to routing; the other five files are the
routing mechanism itself.

## Where to look for what

- **Adding a title-specific quirk?** `docs/protocol/game-quirks.md` and
  `protocol/quirks.rs` (once Stage 4 of the syscall redesign lands) — not a
  new `if` in `kuser_dispatch.rs` or `sigsys_router.rs`.
- **Changing routing behavior?** Start from
  `docs/protocol/syscall-routing.md`'s invariants, then the specific stage
  above that owns the decision you're changing.
- **A CPUID/KUSER/Reflex-protocol question?** `docs/protocol/` first; it's
  the permanent design reference, not scattered across commit messages.
- **Build or release process?** `xtask/src/main.rs`, `.github/workflows/`,
  `install.sh`.
