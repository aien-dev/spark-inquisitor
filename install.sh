#!/bin/sh
set -e

REPO="aien-dev/spark-inquisitor"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

OS=$(uname -s | tr "[:upper:]" "[:lower:]")
ARCH=$(uname -m)

if [ "${OS}" != "linux" ]; then
  echo "Unsupported OS: ${OS}. Currently Linux aarch64 and x86_64 are supported."
  exit 1
fi

case "${ARCH}" in
  x86_64) TARGET_ARCH="x86_64" ;;
  aarch64|arm64) TARGET_ARCH="aarch64" ;;
  *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

echo "Installing spark-inquisitor (${OS}-${TARGET_ARCH}) into ${BIN_DIR}..."

RELEASE_URL="https://github.com/${REPO}/releases/latest/download/spark-inquisitor-linux-${TARGET_ARCH}.tar.gz"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${RELEASE_URL}" -o /tmp/spark-inquisitor.tar.gz
elif command -v wget >/dev/null 2>&1; then
  wget -qO /tmp/spark-inquisitor.tar.gz "${RELEASE_URL}"
else
  echo "Error: curl or wget required."
  exit 1
fi

tar -xzf /tmp/spark-inquisitor.tar.gz -C "${BIN_DIR}" spark-inquisitor
chmod +x "${BIN_DIR}/spark-inquisitor"
rm -f /tmp/spark-inquisitor.tar.gz

echo "spark-inquisitor successfully installed to ${BIN_DIR}/spark-inquisitor"
"${BIN_DIR}/spark-inquisitor" doctor
