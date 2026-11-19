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
    latest_url="$(curl -fsS -o /dev/null -w '%{redirect_url}' "https://github.com/$REPO/releases/latest")"
    case "$latest_url" in
        "https://github.com/$REPO/releases/tag/"*) VERSION="${latest_url##*/}" ;;
        *) VERSION= ;;
    esac
fi
case "$VERSION" in
    ""|*[!A-Za-z0-9._-]*)
        echo "install.sh: could not determine the release to install (got '$VERSION')" >&2
        exit 1
        ;;
esac
asset_url="https://github.com/$REPO/releases/download/$VERSION/Artitux.so"

tmp_lib="$(mktemp)"
tmp_bin=
trap 'rm -f "$tmp_lib" "$LIB_PATH.new" ${tmp_bin:+"$tmp_bin"}' EXIT

echo "artitux: downloading Artitux.so ($VERSION) from $REPO"
curl -fsSL "$asset_url" -o "$tmp_lib"

magic="$(od -An -tx1 -N4 "$tmp_lib" | tr -d ' ')"
if [ "$magic" != "7f454c46" ]; then
    echo "install.sh: downloaded file is not an ELF library, aborting" >&2
    exit 1
fi

mkdir -p "$LIB_DIR" "$BIN_DIR"
tmp_bin="$(mktemp "$BIN_DIR/.artitux.XXXXXX")"
escaped_lib="$(printf '%s' "$LIB_PATH" | sed "s/'/'\\\\''/g")"
{
    cat <<'EOF'
#!/bin/sh
set -eu
set -f

EOF
    printf "lib='%s'\n" "$escaped_lib"
    printf "version='%s'\n" "$VERSION"
    cat <<'EOF'

check() {
    failed=0
    flags="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null || true)"
    if [ -n "$flags" ]; then flags=" ${flags#*:} "; fi
    report() {
        printf '  %-12s %-5s %s\n' "$1" "$2" "$3"
        if [ "$2" = FAIL ]; then failed=1; fi
    }
    has_flag() {
        case "$flags" in *" $1 "*) return 0 ;; esac
        return 1
    }

    echo "artitux $version"
    if [ -r "$lib" ]; then
        report library ok "$lib"
    else
        report library FAIL "not found: $lib (reinstall with install.sh)"
    fi

    if [ -z "$flags" ]; then
        report UMIP unknown "cannot read the CPU flags from /proc/cpuinfo"
    elif ! has_flag umip; then
        report UMIP ok "disabled"
    elif [ -d /sys/module/umip_patch ]; then
        report UMIP ok "enabled, but the umip_patch module is loaded"
    else
        report UMIP FAIL "enabled (see \"Disable UMIP\" in the README)"
    fi

    if [ -z "$flags" ]; then
        report CPUID unknown "cannot read the CPU flags from /proc/cpuinfo"
    elif has_flag cpuid_fault; then
        report CPUID ok "CPUID faulting is supported"
    elif [ -d /sys/module/cpuid_fault_emulation ]; then
        report CPUID ok "CPUID faulting comes from the cpuid_fault_emulation module"
    else
        report CPUID FAIL "CPUID faulting is not available (see \"CPUID faulting on AMD\" in the README)"
    fi

    # Artifact games need the kernel to allow FSGSBASE in user space
    # (AT_HWCAP2 bit 1), the same test the library makes.
    hwcap2="$(LD_SHOW_AUXV=1 /bin/true 2>/dev/null | sed -n 's/^AT_HWCAP2: *//p')"
    case "$hwcap2" in
        0x*[!0-9a-fA-F]*|"") report FSGSBASE unknown "cannot read AT_HWCAP2" ;;
        0x*)
            if [ $((hwcap2 & 2)) -ne 0 ]; then
                report FSGSBASE ok "enabled for user space"
            else
                report FSGSBASE FAIL "not enabled for user space (check for nofsgsbase on the kernel command line)"
            fi
            ;;
        *) report FSGSBASE unknown "cannot read AT_HWCAP2" ;;
    esac

    # Count the CPUs this process may run on, as the library does.
    cpus=unknown
    allowed="$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status 2>/dev/null || true)"
    if [ -n "$allowed" ]; then
        cpus=0
        old_ifs=$IFS
        IFS=,
        for range in $allowed; do
            case "$range" in
                *-*) cpus=$((cpus + ${range#*-} - ${range%-*} + 1)) ;;
                *) cpus=$((cpus + 1)) ;;
            esac
        done
        IFS=$old_ifs
    fi
    if [ -n "${WINE_CPU_TOPOLOGY-}" ]; then
        report CPUs info "$cpus available; WINE_CPU_TOPOLOGY is set, so Artitux uses that value"
    elif [ "$cpus" != unknown ] && [ "$cpus" -gt 16 ]; then
        report CPUs info "$cpus available; Artitux limits Wine to the first 16"
    else
        report CPUs ok "$cpus available"
    fi

    return "$failed"
}

case "${1-}" in
    --version|--check)
        if [ "$#" -ne 1 ]; then
            echo "artitux: $1 does not accept additional arguments" >&2
            exit 2
        fi
        if [ "$1" = --version ]; then
            echo "artitux $version"
            echo "library: $lib"
            exit 0
        fi
        check && exit 0
        exit 1
        ;;
esac

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

# Replace the library and the launcher back to back, each with a rename, so
# an interrupted upgrade does not leave a launcher reporting another release.
chmod 0644 "$tmp_lib"
mv -f "$tmp_lib" "$LIB_PATH.new"
mv -f "$LIB_PATH.new" "$LIB_PATH"
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
echo "To check your system, run:"
echo "  $BIN_PATH --check"

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
