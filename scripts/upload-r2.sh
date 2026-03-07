#!/bin/bash
# Upload tb-manage binaries to Cloudflare R2
set -e

CF_TOKEN=$(op item get dk6zwrwhlqdecoojh64g6khsca --vault "Escape Velocity Ventures Inc." --fields label=password --reveal)
CF_ACCOUNT_ID="538ffcc554cd3507891f3196f193a0e7"
BUCKET="tb-releases"
DIST="$(dirname "$0")"
API="https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/r2/buckets/$BUCKET/objects"

for file in install.sh tb-manage-linux-amd64 tb-manage-linux-arm64 tb-manage-darwin-arm64; do
  echo "Uploading $file..."
  CT="application/octet-stream"
  [ "$file" = "install.sh" ] && CT="text/plain"

  RESULT=$(curl -s -X PUT "$API/$file" \
    -H "Authorization: Bearer $CF_TOKEN" \
    -H "Content-Type: $CT" \
    --data-binary @"$DIST/$file")

  echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  success:', r.get('success', False))" 2>/dev/null || echo "  uploaded (no JSON response)"
done

echo ""
echo "Done. Files uploaded to R2 bucket: $BUCKET"
