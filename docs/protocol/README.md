# Protocol design reference

Permanent design and compatibility reference for the Reflex/Denuvo
protocol Artitux implements. Where the code and these docs disagree, that's
a bug in one of them — fix the discrepancy rather than trusting whichever
was written more recently.

- [`compatibility-overview.md`](compatibility-overview.md) — what this
  project is for, what currently works, and the true state of
  `ARTITUX_SYSCALL_HACK` today.
- [`syscall-routing.md`](syscall-routing.md) — the target design for syscall
  routing: goal, invariants, and the three routing boundaries in source.
- [`game-quirks.md`](game-quirks.md) — per-title CPU identity / KUSER
  recipe / dispatch protocol differences, backing `protocol/quirks.rs`.
- [`topspin-investigation.md`](topspin-investigation.md) — the one open
  compatibility issue currently gating full `ARTITUX_SYSCALL_HACK` removal.

See [`../../README.md`](../../README.md#cpu-and-kernel-prerequisites) for host
UMIP and CPUID-fault prerequisites, and `docs/ARCHITECTURE.md` (repo root
`docs/`) for how these map onto the current source layout.
