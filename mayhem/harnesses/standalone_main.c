/* Standalone run-once driver for the wolfBoot libFuzzer harnesses.
 * Reads a single input file and feeds it to LLVMFuzzerTestOneInput, so a
 * crashing testcase can be replayed without the libFuzzer runtime. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    FILE *f;
    long size;
    uint8_t *data;
    size_t r;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    f = fopen(argv[1], "rb");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s\n", argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) { fclose(f); return 3; }
    data = (uint8_t *)malloc((size_t)size ? (size_t)size : 1);
    if (data == NULL) { fclose(f); return 3; }
    r = fread(data, 1, (size_t)size, f);
    fclose(f);
    (void)r;
    LLVMFuzzerTestOneInput(data, (size_t)size);
    free(data);
    return 0;
}
