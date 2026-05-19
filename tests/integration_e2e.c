#include "daigoro.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef EXE_PATH_MISSING
    #error "Integration tests require a path. Run with: zig build integration -Dexe=\"/path/to/ffxiv_dx11.exe\""
#endif

#ifndef EXE_PATH
    #define EXE_PATH NULL
#endif

int main(void) {
    // Use a uniquely-named temporary cache directory.
    char cache_dir[] = "/tmp/daigoro_e2e_XXXXXX";
    assert(mkdtemp(cache_dir) != NULL);

    // Sanity check
    if (EXE_PATH == NULL) {
        assert(EXE_PATH != NULL && "Missing path: Pass -Dexe to your build command");
    }

    // --- init / encode / decode / destroy ---

    OodleStatus status = oodle_init(EXE_PATH, cache_dir);
    assert(status == OODLE_OK);

    const char src[] = "OodleOodleOodleOodleOodleOodleOodleOodle";
    const uint32_t src_len = (uint32_t)(sizeof(src) - 1);

    const uint32_t max_compressed = oodle_max_compressed_size(src_len);
    uint8_t *compressed = (uint8_t *)malloc(max_compressed);
    assert(compressed != NULL);

    OodleResult r = oodle_encode((const uint8_t *)src, src_len, compressed, max_compressed);
    assert(r.status == OODLE_OK);

    uint8_t *decompressed = (uint8_t *)malloc(src_len);
    assert(decompressed != NULL);

    r = oodle_decode(compressed, r.bytes_written, decompressed, src_len);
    assert(r.status == OODLE_OK);
    assert(memcmp(src, decompressed, src_len) == 0);

    free(decompressed);
    free(compressed);

    // --- double init is rejected ---

    status = oodle_init(EXE_PATH, cache_dir);
    assert(status == OODLE_ERR_ALREADY_INIT);

    // --- destroy and re-init works ---

    oodle_destroy();
    status = oodle_init(EXE_PATH, cache_dir);
    assert(status == OODLE_OK);
    oodle_destroy();

    return 0;
}
