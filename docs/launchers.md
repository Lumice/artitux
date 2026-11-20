# Launchers

Launchers often do not use your shell's `PATH`, so use the full path
`/home/USERNAME/.local/bin/artitux`. Replace `USERNAME` with your user name.

## Steam

Add this line under **Properties > Launch Options**:

```text
/home/USERNAME/.local/bin/artitux %command%
```

Put environment variables before it, for example
`PROTON_LOG=1 /home/USERNAME/.local/bin/artitux %command%`. Flatpak Steam must
be able to read `~/.local/share/artitux/Artitux.so`.

## Gamescope and MangoHud

For normal launches, put `artitux` before the game command:

```text
mangohud /home/USERNAME/.local/bin/artitux %command%
MANGOHUD=1 /home/USERNAME/.local/bin/artitux %command%
```

With Gamescope, put `artitux` before Gamescope so it stays loaded:

```text
/home/USERNAME/.local/bin/artitux gamescope -f -- %command%
/home/USERNAME/.local/bin/artitux gamescope --mangoapp -f -- %command%
```

## Other launchers

- Faugus Launcher: In **Tools > Launch Settings**, set **Launch Arguments**
  (not **Game Arguments**) to `/home/USERNAME/.local/bin/artitux`, without
  `%command%`. For Gamescope, use `/home/USERNAME/.local/bin/artitux gamescope --`.
- Lutris: Open **Configure > Advanced options > System options**. Set **Command
  prefix** to `/home/USERNAME/.local/bin/artitux`.
- Heroic, Bottles, and other frontends: Put `/home/USERNAME/.local/bin/artitux`
  in the game's **Wrapper** or **Command prefix** field.

Flatpak launchers need access to the installed library. If a launcher accepts
only environment variables, set
`LD_PRELOAD=/home/USERNAME/.local/share/artitux/Artitux.so`. The path must not
contain spaces or colons.

## Installer options

To install a specific release, set `ARTITUX_VERSION`. Replace `vX.Y.Z` with a
published release tag:

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | env ARTITUX_VERSION=vX.Y.Z bash
```

The installer writes `~/.local/bin/artitux` and
`~/.local/share/artitux/Artitux.so` and needs no root access. To also create
`/usr/local/bin/artitux`, pass `--global` (asks for `sudo`):

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | bash -s -- --global
```
