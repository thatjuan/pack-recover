#!/bin/sh
# pack-recover installer
# Usage: curl -fsSL https://raw.githubusercontent.com/thatjuan/pack-recover/main/install.sh | sh

set -e

REPO="thatjuan/pack-recover"
BINARY_NAME="pack-recover"
INSTALL_DIR="/usr/local/bin"

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
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        INSTALLED_VERSION=$("$BINARY_NAME" --version 2>/dev/null || echo "unknown")
        success "Installation complete!"
        info "Version: $INSTALLED_VERSION"
        info "Run '$BINARY_NAME --help' to get started"
    else
        warn "Binary installed but not in PATH"
        info "Add $INSTALL_DIR to your PATH or run: $INSTALL_DIR/$BINARY_NAME"
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
