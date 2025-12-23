#!/bin/sh
# pack-recover installer
# Usage: curl -fsSL https://raw.githubusercontent.com/thatjuan/pack-recover/main/install.sh | sh

set -e

REPO="thatjuan/pack-recover"
BINARY_NAME="pack-recover"
INSTALL_DIR="/usr/local/bin"
CARGO_BIN_DIR="$HOME/.cargo/bin"
PATH_UPDATED=0
UPDATED_SHELL_CONFIG=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
    exit 1
}

# Detect the user's shell and config file
detect_shell_config() {
    # Get the user's default shell
    USER_SHELL=$(basename "${SHELL:-/bin/sh}")

    case "$USER_SHELL" in
        bash)
            # On macOS, prefer .bash_profile for login shells
            # On Linux, prefer .bashrc
            if [ "$(uname -s)" = "Darwin" ]; then
                if [ -f "$HOME/.bash_profile" ]; then
                    SHELL_CONFIG="$HOME/.bash_profile"
                elif [ -f "$HOME/.bashrc" ]; then
                    SHELL_CONFIG="$HOME/.bashrc"
                else
                    SHELL_CONFIG="$HOME/.bash_profile"
                fi
            else
                if [ -f "$HOME/.bashrc" ]; then
                    SHELL_CONFIG="$HOME/.bashrc"
                elif [ -f "$HOME/.bash_profile" ]; then
                    SHELL_CONFIG="$HOME/.bash_profile"
                else
                    SHELL_CONFIG="$HOME/.bashrc"
                fi
            fi
            SHELL_NAME="Bash"
            PATH_EXPORT_CMD="export PATH=\"\$PATH:$1\""
            ;;
        zsh)
            SHELL_CONFIG="$HOME/.zshrc"
            SHELL_NAME="Zsh"
            PATH_EXPORT_CMD="export PATH=\"\$PATH:$1\""
            ;;
        fish)
            SHELL_CONFIG="$HOME/.config/fish/config.fish"
            SHELL_NAME="Fish"
            PATH_EXPORT_CMD="fish_add_path $1"
            ;;
        *)
            # Default to .profile for POSIX shells
            SHELL_CONFIG="$HOME/.profile"
            SHELL_NAME="Shell"
            PATH_EXPORT_CMD="export PATH=\"\$PATH:$1\""
            ;;
    esac
}

# Check if a directory is already in PATH
is_in_path() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Add directory to PATH via shell config
add_to_path() {
    TARGET_DIR="$1"

    # Check if already in PATH
    if is_in_path "$TARGET_DIR"; then
        info "$TARGET_DIR is already in PATH"
        return 0
    fi

    # Detect shell and config file
    detect_shell_config "$TARGET_DIR"

    # Create config file if it doesn't exist
    if [ ! -f "$SHELL_CONFIG" ]; then
        mkdir -p "$(dirname "$SHELL_CONFIG")"
        touch "$SHELL_CONFIG"
    fi

    # Check if we've already added this path to the config
    if grep -q "pack-recover PATH" "$SHELL_CONFIG" 2>/dev/null; then
        info "PATH entry already exists in $SHELL_CONFIG"
        return 0
    fi

    info "Adding $TARGET_DIR to PATH in $SHELL_CONFIG..."

    # Add PATH export to shell config
    {
        echo ""
        echo "# pack-recover PATH"
        echo "$PATH_EXPORT_CMD"
    } >> "$SHELL_CONFIG"

    success "Added $TARGET_DIR to PATH in $SHELL_CONFIG"

    # Set flag to remind user to reload shell
    PATH_UPDATED=1
    UPDATED_SHELL_CONFIG="$SHELL_CONFIG"
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            case "$ARCH" in
                x86_64|amd64)
                    PLATFORM="x86_64-unknown-linux-gnu"
                    ;;
                aarch64|arm64)
                    PLATFORM="aarch64-unknown-linux-gnu"
                    ;;
                *)
                    error "Unsupported architecture: $ARCH"
                    ;;
            esac
            ;;
        darwin)
            case "$ARCH" in
                x86_64|amd64)
                    PLATFORM="x86_64-apple-darwin"
                    ;;
                aarch64|arm64)
                    PLATFORM="aarch64-apple-darwin"
                    ;;
                *)
                    error "Unsupported architecture: $ARCH"
                    ;;
            esac
            ;;
        *)
            error "Unsupported operating system: $OS"
            ;;
    esac

    info "Detected platform: $PLATFORM"
}

# Check for required commands
check_dependencies() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
        fi
    done
}

# Get the latest release version
get_latest_version() {
    info "Fetching latest release..."

    LATEST_RELEASE=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || echo "")

    if [ -z "$LATEST_RELEASE" ]; then
        warn "No releases found. Installing from source..."
        install_from_source
        exit 0
    fi

    VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

    if [ -z "$VERSION" ]; then
        warn "Could not determine latest version. Installing from source..."
        install_from_source
        exit 0
    fi

    info "Latest version: $VERSION"
}

# Download and install binary
install_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${VERSION}-${PLATFORM}.tar.gz"

    info "Downloading from: $DOWNLOAD_URL"

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/pack-recover.tar.gz" 2>/dev/null; then
        warn "Binary release not available for $PLATFORM. Installing from source..."
        install_from_source
        return
    fi

    info "Extracting archive..."
    tar -xzf "$TMP_DIR/pack-recover.tar.gz" -C "$TMP_DIR"

    # Find the binary
    BINARY_PATH=$(find "$TMP_DIR" -name "$BINARY_NAME" -type f | head -1)

    if [ -z "$BINARY_PATH" ]; then
        error "Binary not found in archive"
    fi

    # Install binary
    info "Installing to $INSTALL_DIR/$BINARY_NAME..."

    if [ -w "$INSTALL_DIR" ]; then
        cp "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    else
        warn "Need sudo to install to $INSTALL_DIR"
        sudo cp "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi

    success "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"

    # Ensure INSTALL_DIR is in PATH
    add_to_path "$INSTALL_DIR"
}

# Install from source using cargo
install_from_source() {
    info "Installing from source..."

    if ! command -v cargo >/dev/null 2>&1; then
        error "Cargo not found. Please install Rust first: https://rustup.rs/"
    fi

    info "Building with cargo..."
    cargo install --git "https://github.com/${REPO}.git"

    success "Installed $BINARY_NAME via cargo"

    # Ensure cargo bin directory is in PATH
    add_to_path "$CARGO_BIN_DIR"
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        INSTALLED_VERSION=$("$BINARY_NAME" --version 2>/dev/null || echo "unknown")
        success "Installation complete!"
        info "Version: $INSTALLED_VERSION"
        info "Run '$BINARY_NAME --help' to get started"
    else
        if [ "$PATH_UPDATED" = "1" ]; then
            success "Installation complete!"
            warn "Restart your terminal or run:"
            echo ""
            echo "    source $UPDATED_SHELL_CONFIG"
            echo ""
            info "Then run '$BINARY_NAME --help' to get started"
        else
            warn "Binary installed but not in PATH"
            info "Add the install directory to your PATH or run the binary directly"
        fi
    fi
}

# Main installation flow
main() {
    echo ""
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║       pack-recover installer          ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo ""

    check_dependencies
    detect_platform
    get_latest_version
    install_binary
    verify_installation

    echo ""
    success "Done!"
}

main
