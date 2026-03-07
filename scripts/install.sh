#!/bin/sh
# TinkerBelle tb-manage installer
# Usage: curl -fsSL https://get.tinkerbelle.io/install.sh | sh
#   or:  curl -fsSL https://get.tinkerbelle.io/install.sh | sh -s -- --url https://app.tinkerbelle.io
set -e

INSTALL_DIR="/usr/local/bin"
BASE_URL="https://get.tinkerbelle.io"
BINARY="tb-manage"

# Parse arguments
TB_URL=""
TB_IDENTITY="ssh-host-key"
while [ $# -gt 0 ]; do
  case "$1" in
    --url) TB_URL="$2"; shift 2 ;;
    --identity) TB_IDENTITY="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux) ;;
  darwin) ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

DOWNLOAD_URL="${BASE_URL}/${BINARY}-${OS}-${ARCH}"

echo "TinkerBelle tb-manage installer"
echo "  OS:   ${OS}"
echo "  Arch: ${ARCH}"
echo "  URL:  ${DOWNLOAD_URL}"
echo ""

# Download
echo "Downloading tb-manage..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${BINARY}"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$DOWNLOAD_URL" -O "/tmp/${BINARY}"
else
  echo "Error: curl or wget required"
  exit 1
fi

chmod +x "/tmp/${BINARY}"

# Install (may need sudo)
if [ -w "$INSTALL_DIR" ]; then
  mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

echo "Installed: $(${BINARY} --version 2>/dev/null || echo "${INSTALL_DIR}/${BINARY}")"

# Show host key fingerprint (useful for registration)
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then
  FP=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $2}')
  echo ""
  echo "Host key fingerprint: ${FP}"
  echo "Use this to register the node in TinkerBelle SaaS."
fi

# Auto-install as service if --url was provided
if [ -n "$TB_URL" ]; then
  echo ""
  echo "Installing as system service..."
  if [ "$(id -u)" -ne 0 ]; then
    sudo ${BINARY} install --identity "${TB_IDENTITY}" --url "${TB_URL}"
  else
    ${BINARY} install --identity "${TB_IDENTITY}" --url "${TB_URL}"
  fi
  echo ""
  echo "tb-manage is running. Check status with: tb-manage status"
else
  echo ""
  echo "To install as a service:"
  echo "  sudo tb-manage install --identity ssh-host-key --url https://app.tinkerbelle.io"
fi
