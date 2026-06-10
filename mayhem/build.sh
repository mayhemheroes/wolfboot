#!/usr/bin/env bash
#
# wolfboot/mayhem/build.sh — build wolfBoot's OSS-Fuzz firmware/disk-image
# header parsers as sanitized libFuzzer targets (+ standalone reproducers),
# plus a small golden GPT-parse oracle for mayhem/test.sh.
#
# Fuzzed surface (parsers reached on attacker-controlled image bytes, all
# before signature verification or on untrusted disk media):
#   fuzz_elf   — src/elf.c  elf_load_image_mmu()/elf_open(): ELF firmware
#                image header + program-header table walk.
#   fuzz_gpt   — src/gpt.c  gpt_check_mbr_protective()/gpt_parse_header()/
#                gpt_parse_partition(): protective-MBR + GPT header/entry
#                parsing from untrusted disk sectors (x86 FSP boot).
#   fuzz_gzip  — src/gzip.c wolfBoot_gunzip(): clean-room DEFLATE inflater
#                run on gzip-wrapped FIT payloads before verification.
#   fuzz_delta — src/delta.c wb_patch_init()/wb_patch(): Bentley/McIlroy
#                delta-update patch-stream parser.
#
# Strategy mirrors the upstream OSS-Fuzz build: drive wolfBoot's own Makefile
# with config/examples/library.config (TARGET=library, ARCH=sim host build,
# includes wolfCrypt) to produce libwolfboot.a, switching in the module knobs
# the parsers need (ELF=1 GZIP=1 DELTA_UPDATES=1), then compiling src/gpt.o
# and src/fdt.o (not gated by a top-level switch) via the same pattern rules
# so every object agrees on CFLAGS/instrumentation. Sanitizers reach the
# library through the upstream CFLAGS_EXTRA hook.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/
# LIB_FUZZING_ENGINE/SRC). The library + parser objects are built WITH
# $SANITIZER_FLAGS so the fuzzed code (not just the harness) is instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds
# with NO sanitizers; +fuzzer-no-link gives libFuzzer coverage on the library.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

SRC="${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
INCS="-I$SRC/include -I$SRC/tools/unit-tests"

# wolfBoot's library config recipe.
cp config/examples/library.config .config

# Sanitizer flags + coverage instrumentation for the library build. The two
# -Wno-error knobs match upstream OSS-Fuzz: NO_LOADER leaves a static forward
# declaration unused (undefined-internal under -Werror); PRINTF_ENABLED keeps
# the gzip/delta debug stubs linkable.
EXTRA="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link -DPRINTF_ENABLED -Wno-error=undefined-internal -Wno-error"

# ── 1) Build libwolfboot.a (+ the two ungated parsers) with the same flags ──
make -j"$MAYHEM_JOBS" libwolfboot.a \
    CC="$CC" \
    ELF=1 GZIP=1 DELTA_UPDATES=1 \
    CFLAGS_EXTRA="$EXTRA"

make -j"$MAYHEM_JOBS" src/gpt.o src/fdt.o \
    CC="$CC" \
    CFLAGS_EXTRA="$EXTRA -DWOLFBOOT_FDT"

ar rcs libwolfboot.a src/gpt.o src/fdt.o

LIBWB="$SRC/libwolfboot.a"

# Standalone run-once driver (no libFuzzer runtime) compiled once.
$CC $SANITIZER_FLAGS -c "$HARNESS_DIR/standalone_main.c" -o "$SRC/standalone_main.o"

# ── 2) Each harness twice: libFuzzer (-> /mayhem/<name>) + standalone ───────
# Per-module defines line up the header guards with how the parser compiled.
build_harness() {
    local name="$1" defs="$2"
    # libFuzzer target -> /mayhem/<name>
    $CC $SANITIZER_FLAGS $defs -DPRINTF_ENABLED -DARCH_FLASH_OFFSET=0 $INCS \
        -c "$HARNESS_DIR/${name}.c" -o "$SRC/${name}.o"
    $CXX $SANITIZER_FLAGS \
        "$SRC/${name}.o" "$LIBWB" $LIB_FUZZING_ENGINE \
        -o "/mayhem/${name}"
    # standalone reproducer -> /mayhem/<name>-standalone
    $CXX $SANITIZER_FLAGS \
        "$SRC/${name}.o" "$SRC/standalone_main.o" "$LIBWB" \
        -o "/mayhem/${name}-standalone"
    echo "built ${name} (+ standalone)"
}

build_harness fuzz_elf   "-DWOLFBOOT_ELF"
build_harness fuzz_gpt   ""
build_harness fuzz_gzip  "-DWOLFBOOT_GZIP"
build_harness fuzz_delta "-DDELTA_UPDATES -DDELTA_BLOCK_SIZE=512"

# ── 3) Golden GPT-parse oracle for mayhem/test.sh ───────────────────────────
# Linked against the same gpt.o folded into libwolfboot.a. The library objects
# carry ASan/UBSan + sancov(fuzzer-no-link) instrumentation, so the oracle must
# be compiled+linked WITH $SANITIZER_FLAGS to resolve the runtime callbacks
# (__asan_*, __sanitizer_cov_*). This also keeps the oracle itself sanitized —
# a known-answer test under ASan/UBSan is a strictly stronger PATCH oracle.
$CC $SANITIZER_FLAGS $INCS -DARCH_FLASH_OFFSET=0 \
    "$SRC/mayhem/oracle_gpt.c" "$LIBWB" \
    -o "$SRC/mayhem/oracle_gpt"
echo "built mayhem/oracle_gpt"

echo "build.sh complete:"
ls -la /mayhem/fuzz_elf /mayhem/fuzz_gpt /mayhem/fuzz_gzip /mayhem/fuzz_delta \
       /mayhem/fuzz_elf-standalone /mayhem/fuzz_gpt-standalone \
       /mayhem/fuzz_gzip-standalone /mayhem/fuzz_delta-standalone 2>&1 || true
