#!/usr/bin/env bash
# Mount a Windows SMB/CIFS share on the Linux Docker host for CKL export.
#
# Usage:
#   sudo bash scripts/mount-ckl-smb-share.sh //fileserver.example.com/stig-ckl /mnt/stig-ckl-export
#
# Then in .env:
#   CKL_EXPORT_ALLOWED_ROOTS=/data/reports,/data/ckl-exports,/mnt/stig-ckl-export
#
# And in docker-compose.yml (web + worker volumes):
#   - /mnt/stig-ckl-export:/mnt/stig-ckl-export
#
# Schedule CKL export path:
#   /mnt/stig-ckl-export
#
set -euo pipefail

UNC="${1:-}"
MOUNT_POINT="${2:-/mnt/stig-ckl-export}"

if [ -z "$UNC" ]; then
  echo "Usage: sudo $0 //server/share [/mnt/mount-point]"
  echo "Example: sudo $0 //winfile01.contoso.local/STIG-CKL /mnt/stig-ckl-export"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo) to mount CIFS shares."
  exit 1
fi

if ! command -v mount.cifs >/dev/null 2>&1; then
  echo "Installing cifs-utils..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y cifs-utils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y cifs-utils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y cifs-utils
  else
    echo "Install cifs-utils manually, then re-run this script."
    exit 1
  fi
fi

CREDS_FILE="${CREDS_FILE:-/etc/stig-tool/smb-credentials}"
mkdir -p "$(dirname "$CREDS_FILE")" "$MOUNT_POINT"

if [ ! -f "$CREDS_FILE" ]; then
  echo "Creating credentials file at $CREDS_FILE"
  echo "Enter SMB username (DOMAIN\\\\user or user@domain):"
  read -r SMB_USER
  echo "Enter SMB password:"
  read -rs SMB_PASS
  echo
  cat >"$CREDS_FILE" <<EOF
username=${SMB_USER}
password=${SMB_PASS}
EOF
  chmod 600 "$CREDS_FILE"
  echo "Saved. Edit $CREDS_FILE if you need domain=YOURDOMAIN"
fi

if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
  echo "Already mounted: $MOUNT_POINT"
  exit 0
fi

mount -t cifs "$UNC" "$MOUNT_POINT" \
  -o "credentials=${CREDS_FILE},uid=$(id -u),gid=$(id -g),file_mode=0664,dir_mode=0775,vers=3.0"

echo "Mounted $UNC at $MOUNT_POINT"
echo ""
echo "Next steps:"
echo "  1. Add to docker-compose.yml (web + worker):"
echo "       - ${MOUNT_POINT}:${MOUNT_POINT}"
echo "  2. Add to .env:"
echo "       CKL_EXPORT_ALLOWED_ROOTS=/data/reports,/data/ckl-exports,${MOUNT_POINT}"
echo "  3. docker compose restart web worker"
echo "  4. Schedule CKL export path: ${MOUNT_POINT}"
echo ""
echo "Optional /etc/fstab entry (auto-mount on boot):"
echo "  ${UNC} ${MOUNT_POINT} cifs credentials=${CREDS_FILE},uid=1000,gid=1000,file_mode=0664,dir_mode=0775,vers=3.0,_netdev 0 0"
