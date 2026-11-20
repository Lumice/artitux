# Configuration

Set these variables before the wrapper in the launch options, for example
`ARTITUX_DEBUG=1 /home/USERNAME/.local/bin/artitux %command%`.

| Variable | Effect |
| --- | --- |
| `ARTITUX_VBS20=1` or `0` | Forces VBS 2.0 or VBS 1.9 mode instead of the automatic choice. See [vbs-2.0.md](vbs-2.0.md) |
| `ARTITUX_DEBUG=1` | Turns on diagnostics |
| `ARTITUX_LOG=/absolute/path.log` | Writes diagnostics to a private file |
| `ARTITUX_STEAM_IDS=0` | Turns off the [Steam app ID](#steam-app-id) handling |
| `PROTON_AVX=1` | Reports AVX in the default CPU presentation |
| `ARTITUX_SYSCALL_HACK=1` | Makes Wine use the direct syscall path. Only for titles that need it |
| `ARTITUX_LEGACY_PROFILE=1` | Uses the LinUwUx CPU presentation |
| `ARTITUX_WIN32U_FREE_GUARD=1` | Guards against a duplicate `free` in `win32u` |
| `ARTITUX_RESOLVER_BRIDGE=0` | Diagnosis only. Artifact games need the bridge |
| `ARTITUX_ARTIFACT_NATIVE_STUBS=0` | Diagnosis only. Artifact games need the stubs |
| `ARTITUX_SYSCALL_LEAK_TRAP=0` | Diagnosis only. Turns off the guard against Windows syscalls that slip past Wine's syscall dispatch |

## Set automatically

Artitux sets `PROTON_DISABLE_LSTEAMCLIENT=1` unless it is already set.

On CPUs with more than 16 threads, it also limits Wine to 16 CPUs with
`WINE_CPU_TOPOLOGY`, because Artifact reports at most 16. Without this, games
such as Planet Zoo 2 stop at startup. Your own `WINE_CPU_TOPOLOGY` value takes
precedence.

## Steam app ID

Steam releases include a `steam_settings/steam_appid.txt` file next to the
game's `.exe`. The wrapper reads the app ID from that file and passes it to the
game. Without this, games added to Steam as non-Steam games can close at
startup. F1 25 is one of them.

To turn this off, set `ARTITUX_STEAM_IDS=0`.
