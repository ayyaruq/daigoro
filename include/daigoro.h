// include/daigoro.h
#ifndef DAIGORO_H
#define DAIGORO_H

#include <stdint.h>

// OodleStatus is returned by every fallible function.
// Callers should switch on the status rather than testing for OODLE_OK alone,
// since the set of error codes may grow between library versions.
typedef enum OodleStatus {
    OODLE_OK                  = 0,

    // Initialisation errors. These are only possible from oodle_init.
    OODLE_ERR_FILE_NOT_FOUND  = 1,  // exe_path does not exist
    OODLE_ERR_FILE_READ       = 2,  // file exists but could not be read fully
    OODLE_ERR_NOT_PE          = 3,  // DOS magic or PE signature not found
    OODLE_ERR_WRONG_ARCH      = 4,  // PE is not x86-64 (PE32+ magic 0x20B)
    OODLE_ERR_ALLOC           = 5,  // mmap or allocator failure
    OODLE_ERR_RELOC           = 6,  // relocation table contains unknown type
    OODLE_ERR_SIG_NOT_FOUND   = 7,  // one or more byte patterns found no match
    OODLE_ERR_PATCH_GUARD     = 8,  // NOP target bytes did not match expected
    OODLE_ERR_NOT_INIT        = 9,  // oodle_init not called yet
    OODLE_ERR_ALREADY_INIT    = 10,  // oodle_init called more than once

    // Runtime errors. These are only possible from oodle_decode/oodle_encode.
    OODLE_ERR_DECODE_FAILED   = 11, // Oodle returned false from decode
    OODLE_ERR_ENCODE_FAILED   = 12, // Oodle returned <= 0 from encode, or dst_len > oodle_max_compressed_size()
} OodleStatus;

// OodleResult bundles a status with the number of bytes written to the output
// buffer. bytes_written is only meaningful when status == OODLE_OK.
typedef struct OodleResult {
    OodleStatus status;
    uint32_t    bytes_written;
} OodleResult;

// oodle_init loads and prepares the Oodle functions from the game binary.
//
// exe_path: null-terminated UTF-8 path to ffxiv_dx11.exe. The pointer
// is not retained after the function returns.
//
// cache_dir: null-terminated UTF-8 path to a directory for signature cache
// files. If NULL, the library resolves a default location:
//   1. $XDG_CACHE_HOME/daigoro     if XDG_CACHE_HOME is set
//   2. $HOME/.cache/daigoro        if HOME is set
//   3. ./                          current working directory (fallback)
// The directory is created if it does not exist. Pass an explicit path to
// override, which is recommended for system-wide installations.
//
// Returns OODLE_OK on success, or an OODLE_ERR_* value on failure.
// On failure the library remains uninitialised and oodle_init may be retried.
// On OODLE_ERR_ALREADY_INIT the existing state is not modified.
OodleStatus oodle_init(const char* exe_path, const char* cache_dir);

// oodle_destroy releases all resources and resets the library to
// uninitialised. Safe to call when uninitialised (no-op). After this call,
// oodle_init may be called again.
void oodle_destroy(void);

// oodle_max_compressed_size returns the minimum output buffer size that
// oodle_encode requires for an input of the given length.
// Currently uncompressed_len + 8 per the Oodle contract, but callers should
// call this function rather than hardcoding the constant.
uint32_t oodle_max_compressed_size(uint32_t uncompressed_len);

// oodle_decode decompresses a single compressed Zone frame payload.
//
// src, src_len: the compressed input as received from the network, after
// stripping the FFXIV frame header.
//
// dst, dst_len: caller-allocated output buffer. dst_len MUST equal
// FFXIVARR_PACKET_HEADER.decompressedSize from the frame header. Passing a
// wrong dst_len will produce garbled output or an Oodle decode failure.
//
// src and dst must not overlap.
//
// On OODLE_ERR_DECODE_FAILED, dst is zeroed to dst_len bytes and the Oodle
// state remains valid for subsequent calls. The caller should log and discard
// the frame.
OodleResult oodle_decode(
    const uint8_t*  src,
    uint32_t        src_len,
    uint8_t*        dst,
    uint32_t        dst_len
);

// oodle_encode compresses src into dst.
//
// dst_len must be at least oodle_max_compressed_size(src_len). If it is not,
// OODLE_ERR_ENCODE_FAILED is returned immediately without calling Oodle.
//
// On success, bytes_written holds the actual compressed length, which will
// be less than or equal to dst_len. The caller should use bytes_written, not
// dst_len, as the size of the compressed output.
//
// Encode is provided primarily to support round-trip testing. It shares the
// same Oodle state as decode, so encoding and decoding against the same
// instance should be consistent.
OodleResult oodle_encode(
    const uint8_t*  src,
    uint32_t        src_len,
    uint8_t*        dst,
    uint32_t        dst_len
);

// oodle_last_error returns a human-readable description of the most recent
// error, or an empty string if no error has occurred. The returned pointer is
// valid until the next call to any library function on any thread. The caller
// must not free it. Use this for logging only; use OodleStatus for control
// flow.
const char* oodle_last_error(void);

#endif // DAIGORO_H
