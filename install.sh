#!/bin/sh
# cert-renewal - Linux installer (issue #23, spec section 9)
#
#   curl -fsSL https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/install.sh -o install.sh
#   sudo sh install.sh                    # add -DryRun to see what bootstrap WOULD do
#
# This script does as little as possible. It installs PowerShell if the box has none, fetches the
# release manifest, verifies bootstrap.ps1 against it, and hands over. Everything that actually
# configures the machine lives in bootstrap.ps1, which is signed, hashed and versioned - this file
# is only the part that cannot be written in PowerShell, because there is no PowerShell yet.
#
# POSIX sh (developed and tested under dash, which is /bin/sh on Debian and Ubuntu). No
# dependencies beyond curl, sha256sum and the distro package manager. Every argument is passed
# through to bootstrap.ps1 verbatim, so -DryRun and -ManifestUrl mean the same here as there.
set -eu

SCRIPT_VERSION='2.11.0'    # stamped by the release workflow, like the .ps1 scripts
MIRROR='https://raw.githubusercontent.com/iteam-as/public-certrenewal/main'
DOCS='https://github.com/iteam-as/public-certrenewal#readme'
MS_DOCS='https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux'

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
cert-renewal installer $SCRIPT_VERSION

  sudo sh install.sh [-DryRun] [-ManifestUrl <url>] [...]

Installs PowerShell if absent, verifies bootstrap.ps1 against the signed release manifest, and
runs it. All arguments are passed through to bootstrap.ps1 unchanged.

  -DryRun               bootstrap reports what it WOULD do and changes nothing
  -ManifestUrl <url>    use a different manifest (default: the public mirror)
  -h, --help            this text

Guide: $DOCS
EOF
}

# ---------------------------------------------------------------- arguments
# Parsed only to the extent this script needs them; "$@" still reaches bootstrap intact.
MANIFEST_URL="$MIRROR/manifest.json"
for arg in "$@"; do
    case "$arg" in
        -h|--help|-Help) usage; exit 0 ;;
    esac
done
# -ManifestUrl takes the NEXT argument. Walk the list rather than shifting, so "$@" stays whole.
prev=''
for arg in "$@"; do
    case "$prev" in
        -ManifestUrl|-manifesturl) MANIFEST_URL="$arg" ;;
    esac
    prev="$arg"
done

# ---------------------------------------------------------------- privileges
# Everything from here needs root: package installation, /etc, /opt, systemd. Ask for it once,
# up front, rather than letting bootstrap fail halfway through its work.
SUDO=''
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "run this as root (no sudo on this box): su - -c 'sh $0'"
    SUDO='sudo'
    say "Not running as root - using sudo (you may be prompted for your password)."
fi

# ---------------------------------------------------------------- prerequisites
# Both are present on every server image this supports, but a minimal container or a netinst
# Debian can lack curl - and "curl: not found" three steps in is a worse error than this one.
missing=''
for tool in curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    if   command -v apt-get >/dev/null 2>&1; then fix="sudo apt-get install -y curl coreutils"
    elif command -v dnf     >/dev/null 2>&1; then fix="sudo dnf install -y curl coreutils"
    else                                          fix="install them with your package manager"
    fi
    die "this script needs:$missing
  $fix"
fi

TMP="$(mktemp -d)"
# Not 'exec'ed below precisely so this runs: an exec would replace the shell and leak the
# directory, and it holds a downloaded script.
trap 'rm -rf "$TMP"' EXIT INT TERM

# ---------------------------------------------------------------- 1. PowerShell
install_powershell_apt() {
    # ID/VERSION_ID map straight onto the packages.microsoft.com layout for Debian and Ubuntu.
    url="https://packages.microsoft.com/config/$1/$2/packages-microsoft-prod.deb"
    say "  fetching $url"
    curl -fsSL "$url" -o "$TMP/packages-microsoft-prod.deb" || return 1
    $SUDO dpkg -i "$TMP/packages-microsoft-prod.deb" >/dev/null
    $SUDO apt-get update -qq
    # powershell-lts is the 7.4 LTS channel. The fleet is pinned to LTS deliberately: a renewal
    # that runs unattended at 03:00 should not follow a fast-moving release train.
    $SUDO apt-get install -y -qq powershell-lts
}

install_powershell_dnf() {
    url="https://packages.microsoft.com/config/rhel/$1/prod.repo"
    say "  fetching $url"
    curl -fsSL "$url" -o "$TMP/microsoft-prod.repo" || return 1
    $SUDO cp "$TMP/microsoft-prod.repo" /etc/yum.repos.d/microsoft-prod.repo
    $SUDO dnf install -y powershell-lts
}

step "PowerShell"
if command -v pwsh >/dev/null 2>&1; then
    say "  already installed: $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null || echo 'version unknown')"
else
    [ -r /etc/os-release ] || die "no /etc/os-release - cannot identify this distribution. Install PowerShell 7.4 LTS yourself ($MS_DOCS) and run this script again."
    # shellcheck disable=SC1091
    . /etc/os-release
    say "  not installed; this is ${PRETTY_NAME:-$ID $VERSION_ID}"
    installed=0
    if command -v apt-get >/dev/null 2>&1; then
        install_powershell_apt "$ID" "$VERSION_ID" && installed=1
    elif command -v dnf >/dev/null 2>&1; then
        install_powershell_dnf "${VERSION_ID%%.*}" && installed=1
    fi
    if [ "$installed" -ne 1 ]; then
        # Deliberately not a dead end. The package step is a convenience, and every distro this
        # cannot handle - SUSE, Arch, anything unusual - still works perfectly once pwsh exists,
        # so point at the vendor instructions and let the operator come back.
        die "could not install PowerShell automatically on this distribution.
  Install PowerShell 7.4 LTS yourself, then run this script again - it will pick it up:
    $MS_DOCS"
    fi
    command -v pwsh >/dev/null 2>&1 || die "PowerShell installed but 'pwsh' is still not on PATH."
    say "  installed: $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')"
fi

# ---------------------------------------------------------------- 2. manifest
# Flatten to one line, pull out the named object, then the key. The manifest is generated by our
# own release workflow with flat one-level objects, so this is enough - and it avoids requiring
# jq, which is not installed by default anywhere.
json_field() { tr -d '\n\r' < "$TMP/manifest.json" |
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*{\\([^}]*\\)}.*/\\1/p" |
    sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"; }
json_top()   { tr -d '\n\r' < "$TMP/manifest.json" |
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"; }

step "Release manifest"
say "  $MANIFEST_URL"
curl -fsSL "$MANIFEST_URL" -o "$TMP/manifest.json" || die "could not fetch the manifest from $MANIFEST_URL"

# The signature is fetched for REPORTING only. This script cannot check it: verification needs the
# pinned public key and the signature is IEEE P1363 r||s, which openssl will not take without a
# DER conversion. bootstrap.ps1 verifies it properly, with the key pinned in its own source, and
# does so BEFORE it parses the manifest. Saying which of us checks what beats implying this did.
if curl -fsSL "$MANIFEST_URL.sig" -o "$TMP/manifest.json.sig" 2>/dev/null; then
    say "  signature published - bootstrap.ps1 verifies it against the key pinned in its own source"
else
    warn "no manifest.json.sig published at $MANIFEST_URL.sig - bootstrap will apply its signature policy."
fi

BOOTSTRAP_VERSION="$(json_field bootstrap version)"
BOOTSTRAP_URL="$(json_field bootstrap url)"
BOOTSTRAP_SHA="$(json_field bootstrap sha256)"
UPDATED_AT="$(json_top updatedAt)"
[ -n "$BOOTSTRAP_URL" ] || die "the manifest has no bootstrap.url - is $MANIFEST_URL really a cert-renewal manifest?"
# 64 hex characters or the comparison below is meaningless.
case "$BOOTSTRAP_SHA" in
    *[!0-9a-f]*|'') die "the manifest has no usable bootstrap.sha256 ('$BOOTSTRAP_SHA')" ;;
esac
[ "${#BOOTSTRAP_SHA}" -eq 64 ] || die "bootstrap.sha256 is not 64 hex characters ('$BOOTSTRAP_SHA')"
say "  release $BOOTSTRAP_VERSION, published $UPDATED_AT"

# A staleness check, NOT a security gate - and the difference matters. Nothing here can vouch for
# this file: it is the trust root, and it arrived the same way anything used to check it would.
# What the comparison does catch is an old installer kept in someone's notes being run against a
# newer release. A warning, because a deliberately pinned -ManifestUrl is a legitimate reason to
# differ, and because failing closed here would imply a guarantee this script cannot give.
INSTALLER_SHA="$(json_field linuxInstaller sha256)"
if [ -n "$INSTALLER_SHA" ] && [ -r "$0" ]; then
    mine="$(sha256sum "$0" | cut -d' ' -f1)"
    if [ "$mine" != "$INSTALLER_SHA" ]; then
        warn "this installer does not match the one in the manifest (installer $SCRIPT_VERSION, release $BOOTSTRAP_VERSION).
  If that is not deliberate, take a fresh copy:
    curl -fsSL $MIRROR/install.sh -o install.sh"
    fi
fi

# ---------------------------------------------------------------- 3. bootstrap
step "bootstrap.ps1"
say "  $BOOTSTRAP_URL"
curl -fsSL "$BOOTSTRAP_URL" -o "$TMP/bootstrap.ps1" || die "could not download bootstrap.ps1 from $BOOTSTRAP_URL"
ACTUAL_SHA="$(sha256sum "$TMP/bootstrap.ps1" | cut -d' ' -f1)"
# THIS one is a hard gate. The hash comes from a manifest that carries a signature bootstrap will
# verify, so refusing here is refusing to execute bytes the release never vouched for.
[ "$ACTUAL_SHA" = "$BOOTSTRAP_SHA" ] || die "sha256 mismatch for bootstrap.ps1
  downloaded $ACTUAL_SHA
  manifest   $BOOTSTRAP_SHA
  Refusing to run it. Retry; if it persists, report it to the cert team - do not work around this."
say "  sha256 verified against the manifest"

# ---------------------------------------------------------------- 4. hand over
step "Running bootstrap"
set +e
$SUDO pwsh -NoProfile -File "$TMP/bootstrap.ps1" "$@"
status=$?
set -e
if [ "$status" -ne 0 ]; then
    die "bootstrap.ps1 exited $status. It is safe to re-run once the cause is fixed. Guide: $DOCS"
fi
exit 0
