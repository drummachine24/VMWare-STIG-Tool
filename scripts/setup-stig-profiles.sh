#!/usr/bin/env bash
# Download VMware STIG profiles into ./stig-profiles
set -euo pipefail

DEST="${1:-./stig-profiles}"
REPO="https://github.com/vmware/dod-compliance-and-automation.git"
TMP=$(mktemp -d)

echo "Cloning VMware DoD Compliance and Automation repository..."
git clone --depth 1 "$REPO" "$TMP/repo"

echo "Copying VCF 9.x STIG content to $DEST ..."
mkdir -p "$DEST"
if [ -d "$TMP/repo/vcf" ]; then
  cp -r "$TMP/repo/vcf" "$DEST/"
  echo "Installed: $DEST/vcf/"
else
  echo "WARNING: vcf/ directory not found in repository. Check repo structure."
  ls "$TMP/repo"
fi

echo ""
echo "Next: install train-vmware plugin inside the worker container:"
echo "  cinc-auditor plugin install $DEST/vcf/9.x/*/inspec/*/train-vmware-*.gem"
echo ""
echo "Update VCF_PROFILE_BASE in .env if your revision folder differs from Y25M06-srg."

rm -rf "$TMP"
