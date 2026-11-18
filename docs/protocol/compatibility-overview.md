# What Artitux + Reflex are, and are not

Artitux and its companion Reflex client are compatibility tools for running
some legitimately-owned, Denuvo-protected games on Linux. Denuvo-protected
games often fail under Wine because of environment mismatches Wine doesn't
reproduce by default (CPU identity, page/shared-data layout, syscall
dispatch shape). Artitux does not crack or bypass Denuvo: Denuvo's own
license tokens are still required and still enforced by the game; Artitux
only makes the surrounding Linux/Wine environment look enough like Windows
that the protection's own checks pass instead of misfiring.

Reflex plus Artitux route the syscalls a title's protection depends on to a
handler that supplies the arguments the protection expects, rather than
letting a Wine/Linux mismatch present the wrong values and crash or corrupt
game state.

## Current compatibility status

For titles confirmed on Artitux itself, see [COMPATIBILITY.md](../COMPATIBILITY.md)
and the root [README.md](../../README.md#confirmed-titles).

Upstream LinUwUx previously recorded these Reflex-based titles: ACBFR, BGE, FC6,
NFSPB, TopSpin, SMT5V, Hatsune Miku, LADPYIH, and BL4. See
[`game-quirks.md`](game-quirks.md) for the recorded protocol differences;
upstream-only Reflex titles are not currently supported or verified on Artitux.

## Status of `ARTITUX_SYSCALL_HACK`

**Still active in the shipped runtime** (`runtime/src/kuser.rs` writes
`KUSER_SHARED_DATA.SystemCall = 0` for the game process when this is set).
The target design — routing every title without touching that byte at all —
is written up in [`syscall-routing.md`](syscall-routing.md), and is already
close: most titles work with the hack off. It isn't removed project-wide yet
because TopSpin still crashes with it off; see
[`topspin-investigation.md`](topspin-investigation.md) for why, and don't
remove the flag's code path until that's resolved and confirmed on real
hardware.

An additional UMIP-related issue is tracked separately: with UMIP enabled,
some titles can't run at all on Linux, because the kernel returns a dummy
GDTR limit where the game expects `0x7f`. No fix has landed for this from
within Artitux yet; host workarounds are documented in the root
[README.md](../../README.md#cpu-and-kernel-prerequisites).
