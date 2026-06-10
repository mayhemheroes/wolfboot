/* Copyright 2026 Ada Logics Ltd
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* libFuzzer harness for wolfBoot's delta-update patcher (src/delta.c).
 *
 * wb_patch_init() and wb_patch() consume a "patch" stream produced by
 * the host-side delta tool (or, in our threat model, by an attacker)
 * and reconstruct the new firmware image. The patch byte-stream is a
 * custom Bentley/McIlroy-style format with escape-byte framing and
 * variable-length src-offset/length headers -- a clear parser target.
 *
 * Input layout (so that *every* short input drives the parser):
 *   bytes [0..1]  little-endian source-image size, clamped to [1, SRC_SIZE]
 *   bytes [2..]   the patch stream, fed verbatim to wb_patch()
 *
 * The source image is synthesised deterministically from the input bytes
 * (a fixed walking pattern) so that copy/match blocks in the patch read
 * valid source memory. The whole remaining fuzz budget lands on
 * wb_patch()'s ESC-framing / offset / length parsing.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "delta.h"

#define SRC_SIZE  4096
#define DST_BLOCK 512

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 2 header bytes + 1 patch byte. */
    if (size < 3) return 0;

    /* First two bytes: little-endian source-image size, clamped. */
    uint32_t src_sz = (uint32_t)data[0] | ((uint32_t)data[1] << 8);
    if (src_sz < 1) src_sz = 1;
    if (src_sz > SRC_SIZE) src_sz = SRC_SIZE;

    /* Everything after the 2-byte header is the patch stream. */
    const uint8_t *patch_in = data + 2;
    size_t patch_sz = size - 2;

    uint8_t *src = (uint8_t *)malloc(src_sz);
    uint8_t *patch = (uint8_t *)malloc(patch_sz);
    if (!src || !patch) { free(src); free(patch); return 0; }

    /* Deterministic source image: walking pattern seeded by the input. */
    for (uint32_t i = 0; i < src_sz; i++)
        src[i] = (uint8_t)(data[i % size] + i);
    memcpy(patch, patch_in, patch_sz);

    WB_PATCH_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (wb_patch_init(&ctx, src, src_sz,
                      patch, (uint32_t)patch_sz) == 0) {
        uint8_t dst[DST_BLOCK];
        int guard = 0;
        while (guard++ < 4096) {
            int r = wb_patch(&ctx, dst, sizeof(dst));
            if (r <= 0) break;
        }
    }

    free(src);
    free(patch);
    return 0;
}
