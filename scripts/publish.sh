#!/usr/bin/env bash
set -euo pipefail

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
  echo "Usage: $0 <dev|prod>" >&2
  exit 1
}

[[ $# -ne 1 ]] && usage

ENV="$1"

# ─── Environment Configuration ────────────────────────────────────────────────
EC2_OS_USER="ubuntu"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/lovie-ec2-key}"
REMOTE_FIRMWARE_PATH="/home/ubuntu/lovie-app/backend/dist/firmware.bin"

case "$ENV" in
  dev)
    EC2_INSTANCE_ID="i-052c0ffb291fb1155"
    EC2_HOST="52.220.160.5"
    EC2_AZ="ap-southeast-1a"
    ;;
  prod)
    EC2_INSTANCE_ID="i-0155c99a388474761"
    EC2_HOST="47.128.159.107"
    EC2_AZ="ap-southeast-1a"
    ;;
  *)
    echo "ERROR: Unknown environment '$ENV'. Use 'dev' or 'prod'." >&2
    usage
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/../build/merged-binary.bin"
OTA_BINARY="$SCRIPT_DIR/../build/xiaozhi.bin"
FIRMWARE_RELEASE_JSON="$SCRIPT_DIR/../build/firmware-release.json"
REMOTE_OTA_PATH="$(dirname "$REMOTE_FIRMWARE_PATH")/ota.bin"
REMOTE_FIRMWARE_RELEASE_JSON_PATH="$(dirname "$REMOTE_FIRMWARE_PATH")/firmware-release.json"

# ─── Validation ───────────────────────────────────────────────────────────────
if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: Firmware binary not found at $BINARY" >&2
  exit 1
fi

if [[ ! -f "$OTA_BINARY" ]]; then
  echo "ERROR: OTA binary not found at $OTA_BINARY" >&2
  exit 1
fi

if [[ ! -f "$FIRMWARE_RELEASE_JSON" ]]; then
  echo "ERROR: firmware-release.json not found at $FIRMWARE_RELEASE_JSON" >&2
  exit 1
fi

if [[ ! -f "${SSH_KEY}.pub" ]]; then
  echo "ERROR: Public key not found at ${SSH_KEY}.pub" >&2
  echo "Generate one with: ssh-keygen -t ed25519 -f $SSH_KEY -C lovie-ec2" >&2
  exit 1
fi

# ─── 1. Push public key via EC2 Instance Connect ──────────────────────────────
echo "==> [$ENV] Sending public key to EC2 ($EC2_HOST) via Instance Connect..."
aws ec2-instance-connect send-ssh-public-key \
  --no-cli-pager \
  --instance-id "$EC2_INSTANCE_ID" \
  --availability-zone "$EC2_AZ" \
  --instance-os-user "$EC2_OS_USER" \
  --ssh-public-key "file://${SSH_KEY}.pub"

echo "    Key sent (valid for 60 seconds)."

# ─── 2. Ensure remote directory exists ────────────────────────────────────────
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15)
REMOTE_DIR="$(dirname "$REMOTE_FIRMWARE_PATH")"

echo "==> Ensuring remote directory exists: $REMOTE_DIR"
ssh "${SSH_OPTS[@]}" "$EC2_OS_USER@$EC2_HOST" "mkdir -p $REMOTE_DIR"

# ─── 3. Copy firmware binaries ────────────────────────────────────────────────
echo "==> Copying firmware to $EC2_OS_USER@$EC2_HOST:$REMOTE_FIRMWARE_PATH ..."
scp "${SSH_OPTS[@]}" \
  "$BINARY" \
  "$EC2_OS_USER@$EC2_HOST:$REMOTE_FIRMWARE_PATH"

echo "==> Copying OTA binary to $EC2_OS_USER@$EC2_HOST:$REMOTE_OTA_PATH ..."
scp "${SSH_OPTS[@]}" \
  "$OTA_BINARY" \
  "$EC2_OS_USER@$EC2_HOST:$REMOTE_OTA_PATH"

echo "==> Copying firmware-release.json to $EC2_OS_USER@$EC2_HOST:$REMOTE_FIRMWARE_RELEASE_JSON_PATH ..."
scp "${SSH_OPTS[@]}" \
  "$FIRMWARE_RELEASE_JSON" \
  "$EC2_OS_USER@$EC2_HOST:$REMOTE_FIRMWARE_RELEASE_JSON_PATH"

echo ""
echo "==> Done! Firmware published to [$ENV] $EC2_OS_USER@$EC2_HOST:$REMOTE_FIRMWARE_PATH"
echo "==> Done! OTA binary published to [$ENV] $EC2_OS_USER@$EC2_HOST:$REMOTE_OTA_PATH"
echo "==> Done! firmware-release.json published to [$ENV] $EC2_OS_USER@$EC2_HOST:$REMOTE_FIRMWARE_RELEASE_JSON_PATH"
