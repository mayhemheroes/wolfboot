/* mayhem/oracle_gpt.c — golden-output oracle over the SAME code the GPT
 * fuzz harness drives (src/gpt.c: gpt_check_mbr_protective / gpt_parse_header
 * / gpt_parse_partition). wolfBoot's full functional tests need target
 * hardware / emulation, so this is a small self-contained known-answer test
 * over the firmware/disk-image header parse path instead.
 *
 * It builds a byte-exact protective MBR and a byte-exact GPT header from the
 * format documented in include/gpt.h and asserts:
 *   - a well-formed protective MBR is ACCEPTED and yields the right GPT LBA,
 *   - a well-formed GPT header (signature "EFI PART") is ACCEPTED,
 *   - inputs with a corrupted boot signature / partition type / GPT
 *     signature are REJECTED.
 * A no-op / exit(0) patch to the parser cannot pass: every assertion checks
 * an exact accept/reject decision (and a decoded field value) of the real
 * parser. Nonzero exit on any mismatch.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gpt.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do {                                   \
    checks++;                                                    \
    if (!(cond)) { failures++; printf("  FAIL %s\n", msg); }     \
    else { printf("  ok   %s\n", msg); }                        \
} while (0)

/* Put the protective-GPT partition type (0xEE) into MBR entry `idx`, with the
 * given starting LBA, and stamp the 0xAA55 boot signature at 0x1FE. */
static void build_protective_mbr(uint8_t sector[GPT_SECTOR_SIZE],
                                 int idx, uint32_t lba_first) {
    uint8_t *e;
    memset(sector, 0, GPT_SECTOR_SIZE);
    e = sector + GPT_MBR_ENTRY_START + idx * (int)sizeof(struct gpt_mbr_part_entry);
    e[4] = GPT_PTYPE_PROTECTIVE;                 /* ptype */
    /* lba_first lives at offset 8 of the 16-byte entry, little-endian. */
    e[8]  = (uint8_t)(lba_first & 0xff);
    e[9]  = (uint8_t)((lba_first >> 8) & 0xff);
    e[10] = (uint8_t)((lba_first >> 16) & 0xff);
    e[11] = (uint8_t)((lba_first >> 24) & 0xff);
    sector[GPT_MBR_BOOTSIG_OFFSET]     = (uint8_t)(GPT_MBR_BOOTSIG_VALUE & 0xff);
    sector[GPT_MBR_BOOTSIG_OFFSET + 1] = (uint8_t)((GPT_MBR_BOOTSIG_VALUE >> 8) & 0xff);
}

static void build_gpt_header(uint8_t sector[GPT_SECTOR_SIZE]) {
    struct guid_ptable *h = (struct guid_ptable *)sector;
    struct guid_ptable tmp;
    struct gpt_crc32_ctx crc;
    memset(sector, 0, GPT_SECTOR_SIZE);
    h->signature = GPT_SIGNATURE;   /* "EFI PART" */
    h->revision  = 0x00010000;
    h->hdr_size  = 92;              /* 0x5C */
    h->main_lba  = 1;
    h->n_part    = 0;
    h->array_sz  = 128;
    /* Compute the header CRC32 exactly the way gpt_parse_header() verifies it:
     * over the first hdr_size bytes with hdr_crc32 zeroed. */
    h->hdr_crc32 = 0;
    memcpy(&tmp, h, sizeof(tmp));
    tmp.hdr_crc32 = 0;
    gpt_crc32_init(&crc);
    gpt_crc32_update(&crc, (const uint8_t *)&tmp, h->hdr_size);
    h->hdr_crc32 = gpt_crc32_final(&crc);
}

int main(void) {
    uint8_t sector[GPT_SECTOR_SIZE];
    uint32_t lba = 0;
    struct guid_ptable hdr;

    printf("=== wolfBoot GPT header parse oracle ===\n");

    /* 1. Well-formed protective MBR -> accepted, LBA decoded. */
    build_protective_mbr(sector, 0, 1);
    lba = 0;
    CHECK(gpt_check_mbr_protective(sector, &lba) == 0,
          "valid protective MBR is accepted");
    CHECK(lba == 1, "protective MBR LBA decoded as 1");

    /* protective entry in a non-zero slot is still found */
    build_protective_mbr(sector, 2, 34);
    lba = 0;
    CHECK(gpt_check_mbr_protective(sector, &lba) == 0,
          "protective entry in slot 2 is accepted");
    CHECK(lba == 34, "protective MBR LBA decoded as 34");

    /* 2. Corrupt boot signature -> rejected. */
    build_protective_mbr(sector, 0, 1);
    sector[GPT_MBR_BOOTSIG_OFFSET] ^= 0xff;
    CHECK(gpt_check_mbr_protective(sector, NULL) == -1,
          "MBR with bad boot signature is rejected");

    /* 3. Boot signature present but no protective (0xEE) entry -> rejected. */
    memset(sector, 0, GPT_SECTOR_SIZE);
    sector[GPT_MBR_BOOTSIG_OFFSET]     = (uint8_t)(GPT_MBR_BOOTSIG_VALUE & 0xff);
    sector[GPT_MBR_BOOTSIG_OFFSET + 1] = (uint8_t)((GPT_MBR_BOOTSIG_VALUE >> 8) & 0xff);
    CHECK(gpt_check_mbr_protective(sector, NULL) == -1,
          "MBR without a 0xEE protective entry is rejected");

    /* 4. NULL sector -> rejected (defensive contract). */
    CHECK(gpt_check_mbr_protective(NULL, NULL) == -1,
          "NULL MBR sector is rejected");

    /* 5. Well-formed GPT header -> accepted. */
    build_gpt_header(sector);
    memset(&hdr, 0, sizeof(hdr));
    CHECK(gpt_parse_header(sector, &hdr) == 0,
          "valid GPT header (EFI PART) is accepted");
    CHECK(hdr.signature == GPT_SIGNATURE,
          "parsed GPT header signature matches EFI PART");

    /* 6. Corrupt GPT signature -> rejected. */
    build_gpt_header(sector);
    sector[0] ^= 0xff;   /* break the first signature byte */
    memset(&hdr, 0, sizeof(hdr));
    CHECK(gpt_parse_header(sector, &hdr) == -1,
          "GPT header with bad signature is rejected");

    printf("=== %d/%d checks passed ===\n", checks - failures, checks);
    return failures ? 1 : 0;
}
