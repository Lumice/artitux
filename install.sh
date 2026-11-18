#!/usr/bin/env bash
set -euo pipefail

# Everything runs inside main so that a download cut off mid-transfer under
# `curl | bash` cannot execute a partial script.
main() {

case "${1-}" in
    "") ;;
    --help|-h)
        cat <<'USAGE'
Usage: install.sh [--global]

Install Artitux for the current user. The optional --global flag also symlinks
the launcher into /usr/local/bin and may ask for a sudo password.
USAGE
        exit 0
        ;;
    --global)
        if [ "$#" -ne 1 ]; then
            echo "install.sh: --global does not accept additional arguments" >&2
            exit 2
        fi
        ;;
    *)
        echo "install.sh: unknown option: $1" >&2
        echo "Usage: install.sh [--global]" >&2
        exit 2
        ;;
esac

REPO="${ARTITUX_REPO:-Lumice/artitux}"
VERSION="${ARTITUX_VERSION:-latest}"
INSTALL_GLOBAL=0
[ "${1-}" = "--global" ] && INSTALL_GLOBAL=1

LIB_DIR="$HOME/.local/share/artitux"
BIN_DIR="$HOME/.local/bin"
LIB_PATH="$LIB_DIR/Artitux.so"
BIN_PATH="$BIN_DIR/artitux"
GLOBAL_BIN_PATH="/usr/local/bin/artitux"

if [ "$(printf '%s.' "$LIB_PATH" | tr -d ':[:space:]')" != "${LIB_PATH}." ]; then
    echo "install.sh: $LIB_PATH cannot contain ':' or whitespace (it is used in LD_PRELOAD)" >&2
    exit 1
fi

if [ "$VERSION" = "latest" ]; then
    asset_url="https://github.com/$REPO/releases/latest/download/Artitux.so"
else
    asset_url="https://github.com/$REPO/releases/download/$VERSION/Artitux.so"
fi

tmp_lib="$(mktemp)"
tmp_bin=
trap 'rm -f "$tmp_lib" ${tmp_bin:+"$tmp_bin"}' EXIT

echo "artitux: downloading Artitux.so ($VERSION) from $REPO"
curl -fsSL "$asset_url" -o "$tmp_lib"

magic="$(od -An -tx1 -N4 "$tmp_lib" | tr -d ' ')"
if [ "$magic" != "7f454c46" ]; then
    echo "install.sh: downloaded file is not an ELF library, aborting" >&2
    exit 1
fi

mkdir -p "$LIB_DIR" "$BIN_DIR"
install -m 0644 "$tmp_lib" "$LIB_PATH"

tmp_bin="$(mktemp "$BIN_DIR/.artitux.XXXXXX")"
escaped_lib="$(printf '%s' "$LIB_PATH" | sed "s/'/'\\\\''/g")"
{
    cat <<'EOF'
#!/bin/sh
set -eu
set -f

EOF
    printf "lib='%s'\n" "$escaped_lib"
    cat <<'EOF'

if [ ! -r "$lib" ]; then
    echo "artitux: library not found: $lib" >&2
    echo "  Reinstall with install.sh" >&2
    exit 1
fi

case "$lib" in
    *:*)
        echo "artitux: library path cannot contain ':' or whitespace when used in LD_PRELOAD" >&2
        exit 1
        ;;
esac
if [ "$(printf '%s.' "$lib" | tr -d '[:space:]')" != "${lib}." ]; then
    echo "artitux: library path cannot contain ':' or whitespace when used in LD_PRELOAD" >&2
    exit 1
fi

if [ "$#" -eq 0 ]; then
    echo "artitux: no command given -- use it as a launch option:" >&2
    echo "  $0 %command%" >&2
    exit 1
fi

preload="${LD_PRELOAD-}"
command_name="${1##*/}"
filtered=
old_ifs=$IFS
IFS=:
for entry in $preload; do
    [ -n "$entry" ] || continue
    case "$entry" in
        "$lib") continue ;;
    esac
    if [ "$command_name" = gamescope ]; then
        case "$entry" in
            *gameoverlayrenderer.so*) continue ;;
        esac
    fi
    filtered="${filtered:+$filtered:}$entry"
done
IFS=$old_ifs

export LD_PRELOAD="$lib${filtered:+:$filtered}"
exec "$@"
EOF
} >"$tmp_bin"
chmod 0755 "$tmp_bin"
mv -f "$tmp_bin" "$BIN_PATH"
tmp_bin=

if [ "$INSTALL_GLOBAL" -eq 1 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "install.sh: --global requires sudo" >&2
        exit 1
    fi
    echo "artitux: installing global launcher to $GLOBAL_BIN_PATH"
    sudo ln -sf "$BIN_PATH" "$GLOBAL_BIN_PATH"
fi

echo "artitux: installed library to $LIB_PATH"
echo "artitux: installed launcher to $BIN_PATH"

if [ "$INSTALL_GLOBAL" -eq 1 ]; then
    echo "artitux: global launcher installed to $GLOBAL_BIN_PATH"
fi

echo
echo "Set your game's launch command to:"
echo "  $BIN_PATH %command%"

if [ "$INSTALL_GLOBAL" -eq 1 ]; then
    echo
    echo "Bare 'artitux' now resolves through $GLOBAL_BIN_PATH."
else
    echo
    echo "GUI launchers may not inherit $BIN_DIR in PATH. Use the absolute path above"
    echo "for Steam, Faugus, Lutris, and other desktop launchers."
    echo "To make bare 'artitux' available, rerun this installer with --global."
fi

echo
echo "In a launcher that only accepts environment variables, set:"
echo "  LD_PRELOAD=$LIB_PATH"
echo "Keep any existing LD_PRELOAD value and prepend Artitux with a colon."

}

main "$@"
