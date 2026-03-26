#!/bin/bash
set -e

cd "$(dirname "$0")/.."

# Auto-detect function names defined in verify.c (excludes header inlines).
FCTS=$(grep -oP '^static \w+ \K\w+(?=\()' src/arm64/verify.c | paste -sd,)
FCTS="lfiv_verify_arm64,$FCTS"

frama-c -wp -wp-rte \
  frama-c/stubs.c \
  src/arm64/verify.c \
  -cpp-extra-args="-Isrc/include -Isubprojects/disarm -Ibuild/subprojects/disarm -DNDEBUG" \
  -wp-model "Typed+Cast" \
  -wp-prover z3 \
  -wp-timeout 5 \
  -wp-par 16 \
  -wp-skip-fct verrmin,verr,da64_decode,da64_format \
  -wp-fct "$FCTS" \
  -wp-smoke-tests \
  2>&1
