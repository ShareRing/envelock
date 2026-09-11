#!/usr/bin/env bash
# Build and run the buffer registry tests.
#
# Compiles against React Native's real JSI headers so the host-function code is type-checked
# too, even though the tests themselves exercise only the C ABI.
set -euo pipefail
cd "$(dirname "$0")/.."

RN="node_modules/react-native/ReactCommon"
[ -d "$RN/jsi" ] || { echo "react-native not installed; run pnpm install" >&2; exit 1; }

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

# jsi.cpp is linked in so the host-function code is compiled and linked for real, not just
# parsed. The tests themselves drive the C ABI, which needs no JavaScript runtime.
clang++ -std=c++17 -Wall -Wextra -g -fsanitize=address,undefined \
  -I "$RN/jsi" -I cpp \
  cpp/EnvelockJSI.cpp cpp/EnvelockJSI.test.cpp "$RN/jsi/jsi/jsi.cpp" \
  -o "$OUT/tests"

"$OUT/tests"
