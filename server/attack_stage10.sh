#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="${SCRIPT_DIR}/attack_stage9.sh"

if [ ! -f "$SOURCE_SCRIPT" ]; then
  echo "attack_stage9.sh 파일을 찾을 수 없습니다."
  exit 1
fi

TMP_SCRIPT="$(mktemp /tmp/attack_stage10.XXXXXX.sh)"
cleanup() {
  rm -f "$TMP_SCRIPT"
}
trap cleanup EXIT

sed \
  -e 's/Stage9/Stage10/g' \
  -e 's/stage9-/stage10-/g' \
  "$SOURCE_SCRIPT" > "$TMP_SCRIPT"

chmod +x "$TMP_SCRIPT"
exec "$TMP_SCRIPT"
