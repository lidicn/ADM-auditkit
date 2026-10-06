#!/usr/bin/env bash
set -euo pipefail
# shellcheck shell=bash

TARGET="$1"
[[ -n "$TARGET" ]] || { echo "need target" >&2; exit 1; }
rm -rf -- "${TARGET:?}/build"
