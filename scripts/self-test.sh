#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
cd "$(dirname "$0")/.."

bash -n install.sh
bash -n bin/homelabctl
bash -n bin/hcc-node-helper
bash -n extras/install-node-helper.sh

python3 -m py_compile src/server.py src/actiond.py tests/test_core.py
python3 -m unittest discover -s tests -v

if command -v node >/dev/null 2>&1; then
  node --check src/static/app.js
fi

sha256sum -c manifest.sha256

if grep -R -E '<script[^>]+https?://|@import[[:space:]]+url\(https?://' src/static; then
  echo "Remote browser dependency detected." >&2
  exit 1
fi

if grep -R -E '\.innerHTML[[:space:]]*=' src/static/app.js; then
  echo "Unsafe dynamic innerHTML assignment detected." >&2
  exit 1
fi

echo "All self-tests passed."
