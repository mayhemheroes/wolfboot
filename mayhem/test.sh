#!/usr/bin/env bash
#
# wolfboot/mayhem/test.sh — RUN the golden GPT-parse oracle built by
# mayhem/build.sh and emit a CTRF summary. exit 0 iff no check failed.
#
# wolfBoot's full functional suite requires target hardware / QEMU emulation,
# so the PATCH-grade oracle here is a self-contained known-answer test over
# the SAME parser the GPT fuzz harness drives (src/gpt.c). It asserts exact
# accept/reject decisions and a decoded field value for well-formed vs
# corrupted protective-MBR / GPT-header inputs — a no-op / exit(0) patch to
# the parser cannot pass. This script only RUNS the pre-built binary.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SRC"

ORACLE="$SRC/mayhem/oracle_gpt"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "wolfboot-gpt-oracle" 0 1 0; exit 2
fi

echo "=== running $ORACLE ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# The oracle prints "=== N/M checks passed ===".
line="$(printf '%s\n' "$out" | sed -n 's/^=== \([0-9][0-9]*\)\/\([0-9][0-9]*\) checks passed ===$/\1 \2/p' | tail -1)"
PASSED="${line%% *}"; TOTAL="${line##* }"
if [ -n "$line" ] && [ -n "$PASSED" ] && [ -n "$TOTAL" ]; then
  FAILED=$(( TOTAL - PASSED ))
  emit_ctrf "wolfboot-gpt-oracle" "$PASSED" "$FAILED" 0
else
  echo "could not parse oracle summary; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "wolfboot-gpt-oracle" 1 0 0; exit 0; }
  emit_ctrf "wolfboot-gpt-oracle" 0 1 0; exit 1
fi
