#!/usr/bin/env bash
# ========================================================================
# Simple File Integrity Monitor (FIM)
# Description:
#   - init:  Create a SHA-256 baseline for a directory
#   - scan:  Compare current state vs baseline (modified/new/deleted files)
# Author: Lucas Furno
# License: MIT
# ========================================================================

set -euo pipefail
IFS=$'\n\t'

bold=$(tput bold || true); reset=$(tput sgr0 || true)
green=$(tput setaf 2 || true); yellow=$(tput setaf 3 || true); red=$(tput setaf 1 || true)

usage() {
  cat <<EOF
Usage:
  $0 init  <directory> [baseline_file]
  $0 scan  <directory> [baseline_file]

Notes:
  - Baseline defaults to .fim-baseline in the target directory.
  - Follows regular files only. Symlinks are skipped.
  - You can exclude paths with FIM_EXCLUDES (comma-separated globs).
    Example: FIM_EXCLUDES="*.log,*.tmp,cache/*" $0 init /etc
EOF
}

# --- hash command detection (sha256sum or shasum -a 256) ---
hash_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd="shasum -a 256"
else
  ech
