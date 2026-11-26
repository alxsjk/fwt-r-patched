#!/usr/bin/env bash
# Sets up a self-contained JDK + Android SDK toolchain without root.
#
# Installs Temurin JDK and Android command-line tools under $HOME, then
# installs platform-tools (adb) and build-tools (zipalign/apksigner).
#
# Usage:
#   bash scripts/setup-linux-toolchain.sh
#   ANDROID_SDK_ROOT=/opt/android-sdk bash scripts/setup-linux-toolchain.sh

set -euo pipefail

SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
JDK_DIR="$HOME/tools/jdk"
JDK_MAJOR="${JDK_MAJOR:-21}"
JDK_SHA256="${JDK_SHA256:-}"
BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-35.0.0}"
CMDLINE_TOOLS_URL="${CMDLINE_TOOLS_URL:-https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip}"
CMDLINE_TOOLS_SHA256="${CMDLINE_TOOLS_SHA256:-}"

TMP_DIRS=()
cleanup() {
    if [ "${#TMP_DIRS[@]}" -gt 0 ]; then
        rm -rf "${TMP_DIRS[@]}"
    fi
}
trap cleanup EXIT

for cmd in curl tar unzip sha256sum awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is required" >&2
        exit 1
    fi
done

case "$(uname -m)" in
    x86_64|amd64) JDK_ARCH="x64" ;;
    aarch64|arm64) JDK_ARCH="aarch64" ;;
    *) echo "ERROR: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

verify_sha256() {
    local file="$1"
    local expected="$2"
    if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "ERROR: invalid SHA-256 format for $file: $expected" >&2
        exit 1
    fi
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

mkdir -p "$HOME/tools" "$SDK_ROOT/cmdline-tools"

if [ ! -x "$JDK_DIR/bin/java" ]; then
    echo "Downloading Temurin JDK ${JDK_MAJOR} (${JDK_ARCH})..."
    tmp="$(mktemp -d)"
    TMP_DIRS+=("$tmp")
    curl --proto '=https' --tlsv1.2 -L --fail --silent --show-error \
        -o "$tmp/jdk.tar.gz" \
        "https://api.adoptium.net/v3/binary/latest/${JDK_MAJOR}/ga/linux/${JDK_ARCH}/jdk/hotspot/normal/eclipse"
    expected_jdk_sha="$JDK_SHA256"
    if [ -z "$expected_jdk_sha" ]; then
        curl --proto '=https' --tlsv1.2 -L --fail --silent --show-error \
            -o "$tmp/jdk.sha256" \
            "https://api.adoptium.net/v3/checksum/latest/${JDK_MAJOR}/ga/linux/${JDK_ARCH}/jdk/hotspot/normal/eclipse"
        expected_jdk_sha="$(awk 'NR == 1 { print $1 }' "$tmp/jdk.sha256")"
    fi
    if [ -z "$expected_jdk_sha" ]; then
        echo "ERROR: could not obtain expected SHA-256 for Temurin JDK ${JDK_MAJOR}" >&2
        exit 1
    fi
    verify_sha256 "$tmp/jdk.tar.gz" "$expected_jdk_sha"
    mkdir -p "$HOME/tools/jdk-${JDK_MAJOR}"
    tar -xzf "$tmp/jdk.tar.gz" -C "$HOME/tools/jdk-${JDK_MAJOR}" --strip-components=1
    ln -sfn "$HOME/tools/jdk-${JDK_MAJOR}" "$JDK_DIR"
fi

export JAVA_HOME="$JDK_DIR"
export PATH="$JAVA_HOME/bin:$PATH"

if [ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]; then
    if [ -z "$CMDLINE_TOOLS_SHA256" ]; then
        echo "ERROR: CMDLINE_TOOLS_SHA256 must be set to verify $CMDLINE_TOOLS_URL" >&2
        exit 1
    fi
    echo "Downloading Android command-line tools..."
    tmp="$(mktemp -d)"
    TMP_DIRS+=("$tmp")
    curl --proto '=https' --tlsv1.2 -L --fail --silent --show-error -o "$tmp/cmdtools.zip" "$CMDLINE_TOOLS_URL"
    verify_sha256 "$tmp/cmdtools.zip" "$CMDLINE_TOOLS_SHA256"
    unzip -q "$tmp/cmdtools.zip" -d "$tmp"
    rm -rf "$SDK_ROOT/cmdline-tools/latest.tmp"
    mkdir -p "$SDK_ROOT/cmdline-tools/latest.tmp"
    mv "$tmp/cmdline-tools/"* "$SDK_ROOT/cmdline-tools/latest.tmp/"
    rm -rf "$SDK_ROOT/cmdline-tools/latest"
    mv "$SDK_ROOT/cmdline-tools/latest.tmp" "$SDK_ROOT/cmdline-tools/latest"
fi

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" --sdk_root="$SDK_ROOT" "platform-tools" "build-tools;${BUILD_TOOLS_VERSION}"

echo "--- toolchain ---"
"$SDK_ROOT/build-tools/${BUILD_TOOLS_VERSION}/zipalign" 2>&1 | head -n 1 || true
"$SDK_ROOT/platform-tools/adb" version | head -n 1
java -version 2>&1 | head -n 1
