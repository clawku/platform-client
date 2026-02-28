#!/bin/bash
# Generate Ed25519 signing keys for Tauri updater
# Usage: ./scripts/generate-updater-keys.sh

set -e

KEY_DIR="$HOME/.tauri"
mkdir -p "$KEY_DIR"

PRIVATE_KEY="$KEY_DIR/clawku-updater.key"
PUBLIC_KEY="$KEY_DIR/clawku-updater.pub"

if [ -f "$PRIVATE_KEY" ]; then
  echo "Keys already exist at $KEY_DIR"
  echo ""
  echo "Public key (for tauri.conf.json):"
  openssl pkey -in "$PRIVATE_KEY" -pubout -outform DER 2>/dev/null | base64
  exit 0
fi

# Generate Ed25519 key pair using openssl
echo "Generating Ed25519 key pair..."
openssl genpkey -algorithm Ed25519 -out "$PRIVATE_KEY"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

# Extract base64-encoded public key for tauri.conf.json
PUBKEY_BASE64=$(openssl pkey -in "$PRIVATE_KEY" -pubout -outform DER 2>/dev/null | base64)

echo ""
echo "Keys generated successfully!"
echo ""
echo "Private key: $PRIVATE_KEY"
echo "Public key: $PUBLIC_KEY"
echo ""
echo "=========================================="
echo "Add this public key to tauri.conf.json:"
echo "=========================================="
echo "$PUBKEY_BASE64"
echo ""
echo "=========================================="
echo "For CI/CD builds, set these env vars:"
echo "=========================================="
echo "  TAURI_SIGNING_PRIVATE_KEY=\$(cat $PRIVATE_KEY)"
echo "  TAURI_SIGNING_PRIVATE_KEY_PASSWORD="
echo ""
