#!/usr/bin/env bash
# Closes the audit's packaging findings: excludes .git, IDE metadata, and
# logs from the release archive. Run from the project root.
set -euo pipefail
VERSION=$(python3 -c "import json; print(json.load(open('models/artifacts/current.json'))['version'])" 2>/dev/null || echo "unversioned")
OUT="release_${VERSION}.tar.gz"
tar --exclude='.git' --exclude='.claude' --exclude='__pycache__' \
    --exclude='logs' --exclude='*.log' --exclude='.pytest_cache' \
    -czf "$OUT" .
echo "Wrote $OUT"
