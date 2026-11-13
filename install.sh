#!/usr/bin/env bash
# Open Cloud Agents: Universal Installer (macOS & Linux)
# https://open-cloud-agents.github.io/ocagents/
#
# Usage:
#   curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh | bash
#
set -eo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

log_info() {
    printf "${BLUE}ℹ${RESET} %s\n" "$1"
}

log_pass() {
    printf "  ${GREEN}✔${RESET} %s\n" "$1"
}

log_warn() {
    printf "  ${YELLOW}⚠${RESET} %s\n" "$1"
}

log_fail() {
    printf "  ${RED}✖${RESET} %s\n" "$1" >&2
}

REPO_URL="https://github.com/open-cloud-agents/ocagents.git"
REPO_NAME="open-cloud-agents/ocagents"
RELEASE_TAG="${OCAGENTS_VERSION:-latest}"
INSTALL_DIR="${OCAGENTS_INSTALL_DIR:-$HOME/.open-cloud-agents}"
BIN_DIR="${OCAGENTS_BIN_DIR:-$HOME/.local/bin}"

printf "\n"
printf "${BOLD}☁️  Installing Open Cloud Agents CLI (ocagents)...${RESET}\n"
printf "%s\n" "=================================================================="

# 1. Attempt Standalone Hermetic Binary Download
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
BINARY_NAME=""

case "$OS" in
    darwin)
        case "$ARCH" in
            arm64|aarch64) BINARY_NAME="ocagents-darwin-arm64" ;;
            x86_64) BINARY_NAME="ocagents-darwin-amd64" ;;
        esac
        ;;
    linux)
        case "$ARCH" in
            x86_64) BINARY_NAME="ocagents-linux-amd64" ;;
            arm64|aarch64) BINARY_NAME="ocagents-linux-arm64" ;;
        esac
        ;;
esac

INSTALLED_STANDALONE=false
mkdir -p "$BIN_DIR"

if [ -n "$BINARY_NAME" ]; then
    log_info "Detected platform: ${OS} (${ARCH}). Checking for precompiled binary distribution..."
    ARCHIVE_NAME="${BINARY_NAME}.tar.gz"
    if [ "$RELEASE_TAG" = "latest" ]; then
        ARCHIVE_URL="https://github.com/${REPO_NAME}/releases/latest/download/${ARCHIVE_NAME}"
        DOWNLOAD_URL="https://github.com/${REPO_NAME}/releases/latest/download/${BINARY_NAME}"
    else
        ARCHIVE_URL="https://github.com/${REPO_NAME}/releases/download/${RELEASE_TAG}/${ARCHIVE_NAME}"
        DOWNLOAD_URL="https://github.com/${REPO_NAME}/releases/download/${RELEASE_TAG}/${BINARY_NAME}"
    fi

    APP_DIR="${HOME}/.open-cloud-agents/app"
    TMP_ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/ocagents-archive.XXXXXX.tar.gz")"
    if curl -fsSL "$ARCHIVE_URL" -o "$TMP_ARCHIVE" 2>/dev/null; then
        mkdir -p "$APP_DIR"
        rm -rf "${APP_DIR:?}"/*
        tar -xzf "$TMP_ARCHIVE" -C "$APP_DIR"
        rm -f "$TMP_ARCHIVE"
        chmod +x "$APP_DIR/ocagents"
        ln -sf "$APP_DIR/ocagents" "$BIN_DIR/ocagents"
        ln -sf "$BIN_DIR/ocagents" "$BIN_DIR/oca"
        log_pass "Installed pre-extracted high-performance distribution to: ${APP_DIR} and linked to ${BIN_DIR}/ocagents (${BIN_DIR}/oca)"
        INSTALLED_STANDALONE=true
    else
        rm -f "$TMP_ARCHIVE"
        TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/ocagents-bin.XXXXXX")"
        if curl -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN" 2>/dev/null; then
            chmod +x "$TMP_BIN"
            mv "$TMP_BIN" "$BIN_DIR/ocagents"
            ln -sf "$BIN_DIR/ocagents" "$BIN_DIR/oca"
            log_pass "Installed standalone binary to: ${BIN_DIR}/ocagents and alias ${BIN_DIR}/oca"
            INSTALLED_STANDALONE=true
        else
            rm -f "$TMP_BIN"
            log_warn "Precompiled distribution not yet published for release '${RELEASE_TAG}'. Falling back to local catalog installation..."
        fi
    fi
fi

# 2. Source Catalog Fallback (Requires Python 3 & Git)
if [ "$INSTALLED_STANDALONE" = false ]; then
    # 2a. Check Python 3
    if command -v python3 >/dev/null 2>&1; then
        PY_BIN="python3"
    elif command -v python >/dev/null 2>&1; then
        PY_BIN="python"
    else
        log_fail "Python 3 is required for source installation but was not found on your system."
        printf "   Please install Python 3.9+ via your package manager (brew, apt, dnf, apk).\n"
        exit 1
    fi

    PY_VER=$($PY_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log_pass "Found Python ${PY_VER} (${PY_BIN})"

    # 2b. Check Git
    if ! command -v git >/dev/null 2>&1; then
        log_fail "Git is required for source installation but was not found on your system."
        exit 1
    fi
    log_pass "Found Git: $(git --version | head -n 1)"

    # 2c. Clone or update repository assets
    log_info "Synchronizing canonical agent catalog into: ${INSTALL_DIR}..."
    if [ -d "$INSTALL_DIR/.git" ]; then
        git -C "$INSTALL_DIR" fetch origin main --quiet
        git -C "$INSTALL_DIR" reset --hard origin/main --quiet
        log_pass "Updated existing installation to latest main branch."
    elif [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR" --quiet
        log_pass "Replaced catalog with fresh clone."
    else
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR" --quiet
        log_pass "Cloned canonical catalog successfully."
    fi

    # 2d. Install shell launchers
    LAUNCHER="$BIN_DIR/ocagents"
    cat << 'EOF' > "$LAUNCHER"
#!/usr/bin/env bash
set -eo pipefail
export OCAGENTS_HOME="${OCAGENTS_HOME:-$HOME/.open-cloud-agents}"
if [ -f "$OCAGENTS_HOME/src/ocagents/cli.py" ]; then
    CLI_ENTRY="$OCAGENTS_HOME/src/ocagents/cli.py"
elif [ -f "$(dirname "$0")/../src/ocagents/cli.py" ]; then
    CLI_ENTRY="$(dirname "$0")/../src/ocagents/cli.py"
else
    echo "❌ Error: Open Cloud Agents catalog not found in $OCAGENTS_HOME." >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$CLI_ENTRY" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "$CLI_ENTRY" "$@"
else
    echo "❌ Error: Python 3 is required to run ocagents." >&2
    exit 1
fi
EOF

    chmod +x "$LAUNCHER"
    ln -sf "$LAUNCHER" "$BIN_DIR/oca"
    log_pass "Installed executable launcher to ${LAUNCHER} and alias ${BIN_DIR}/oca"
fi

# 5. Check PATH and configure shell profile if needed
PATH_CONFIGURED=false
case ":$PATH:" in
    *":$BIN_DIR:"*) PATH_CONFIGURED=true ;;
    *) PATH_CONFIGURED=false ;;
esac

CURRENT_SHELL="$(basename "${SHELL:-bash}")"
PROFILE_FILE=""
if [ "$PATH_CONFIGURED" = false ]; then
    if [ "$CURRENT_SHELL" = "zsh" ]; then
        PROFILE_FILE="$HOME/.zshrc"
    elif [ "$CURRENT_SHELL" = "bash" ]; then
        if [ -f "$HOME/.bashrc" ]; then
            PROFILE_FILE="$HOME/.bashrc"
        elif [ -f "$HOME/.bash_profile" ]; then
            PROFILE_FILE="$HOME/.bash_profile"
        else
            PROFILE_FILE="$HOME/.profile"
        fi
    else
        PROFILE_FILE="$HOME/.profile"
    fi

    if [ -n "$PROFILE_FILE" ] && [ -w "$(dirname "$PROFILE_FILE")" ]; then
        if ! grep -q "$BIN_DIR" "$PROFILE_FILE" 2>/dev/null; then
            printf "\n# Open Cloud Agents CLI\nexport PATH=\"%s:\$PATH\"\n" "$BIN_DIR" >> "$PROFILE_FILE"
            log_pass "Appended ${BIN_DIR} to PATH in ${PROFILE_FILE}"
        fi
    fi
fi

# 6. Verification
printf "%s\n" "------------------------------------------------------------------"
log_info "Verifying CLI installation..."
export PATH="$BIN_DIR:$PATH"
"$BIN_DIR/ocagents" info

printf "\n"
printf "${BOLD}${GREEN}🎉 Open Cloud Agents (ocagents) installed successfully!${RESET}\n"
printf "%s\n" "=================================================================="
printf "${BOLD}Quickstart Commands:${RESET}\n"
printf "  • List all agents:          ${BLUE}ocagents -agents list${RESET} (or ${BLUE}ocagents -a ls${RESET})\n"
printf "  • Sync for GitHub Copilot:  ${BLUE}ocagents sync -A --format github --target .${RESET}\n"
printf "  • Sync for Claude Code:     ${BLUE}ocagents sync -A --format claude --target .${RESET}\n"
printf "  • Sync for Cursor:          ${BLUE}ocagents sync -A --format cursor --target .${RESET}\n"
printf "  • Validate specs & tests:   ${BLUE}ocagents validate${RESET}\n"
printf "  • Update agent catalog:     ${BLUE}ocagents update${RESET}\n"
printf "\n"
if [ "$PATH_CONFIGURED" = false ]; then
    printf "${YELLOW}Note: To use 'ocagents' in your current terminal session, run:${RESET}\n"
    printf "  ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n" "$BIN_DIR"
    if [ -n "$PROFILE_FILE" ]; then
        printf "  ${BOLD}source %s${RESET}\n" "$PROFILE_FILE"
    fi
    printf "\n"
fi

