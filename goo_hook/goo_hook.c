/* Injectable Windows DLL for CHITUBOX Pro 2.0.8: hooks CreateFileW/
 * CloseHandle via IAT patching (across every loaded module in the process,
 * not just the main EXE - since the actual file I/O happens deep inside
 * the CRT/librabbit_slice_serial.dll, not chitubox pro.exe's own IAT).
 * When a handle opened for a path ending in ".goo" is closed, reads the
 * finished file back; if it starts with "V3.0" (i.e. CHITUBOX just wrote a
 * v3 file, which is all it natively supports), converts it to a valid v5.1
 * file in place using the byte-exact recipe from GOO_V3_V5_FORMAT_NOTES.md
 * (same logic as goo_v3_to_v5.c, ported here to work on in-memory buffers
 * with plain WinAPI file I/O instead of libc stdio, to minimize CRT
 * surface inside an injected DLL).
 *
 * This makes CHITUBOX Pro's existing "Export" button produce a Jupiter-2-
 * compatible v5 .goo file directly - no visible intermediate v3 file, no
 * separate conversion step.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h> /* va_list, for FL_DebugLog (merged in from ChituHook - see near InstallHooksThread) */

/* Defined in qml_probe.cpp (compiled separately as C++ against the real
 * Qt 6.3.2 headers, linked into this same DLL) - see its own comment for
 * what this does and why it's the ONLY function from that file this
 * thread (InstallHooksThread) is allowed to call directly: it just posts
 * a QMetaObject::invokeMethod(..., Qt::QueuedConnection) call, which is
 * documented thread-safe from any thread, to run the actual Qt-object
 * work on the GUI thread instead - never touches a QQuickItem/QWidget
 * directly from here. (2026-09-08: the earlier version of this file had
 * probe_qml_tree()/fix_network_send_button(), called directly from this
 * thread - that caused a real crash during a real Jupiter-2 Save Slice
 * export, see the long comment that used to be here and is now in
 * qml_probe.cpp's own header instead.) */
extern void schedule_fix_network_send_button(void);

/* ---------- convert_v3_to_v5 (ported from goo_v3_to_v5.c) ---------- */

#define V3_HEADER_FIXED_STR_SIZE (4+8+32+24+24+32+32+32)

static uint32_t gbe32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void gput_le32(uint8_t *p, uint32_t v) {
    p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff;
}

typedef struct { int size; int numeric; } GFieldSpec;
static const GFieldSpec HEADER_TAIL_FIELDS[] = {
    /* AntiAliasingLevel/GreyLevel/BlurLevel removed from here - they sit
     * BEFORE the previews, not in this tail run; flipped separately in
     * convert_v3_to_v5 right after the initial verbatim memcpy. Leaving
     * them here (as the original version of this file did) silently
     * shifted this loop's first 3 reads onto the tail of BigPreview565
     * instead, so they never got flipped (found 2026-09-03 on a real
     * source with non-default aa/grey/blur settings - a v3 aa=1 came out
     * as aa=256 in the v5 output). */
    {4,1},{2,1},{2,1},{1,0},{1,0},
    {4,1},{4,1},{4,1},{4,1},{4,1},
    {1,0},
    {4,1},{4,1},{4,1},{4,1},
    {4,1},{4,1},{4,1},
    {4,1},{4,1},
    {4,1},{4,1},{4,1},{4,1},
    {4,1},{4,1},{4,1},{4,1},
    {4,1},{4,1},{4,1},{4,1},
    {4,1},{4,1},{4,1},{4,1},
    {2,1},{2,1},
    {1,0},
    {4,1},{4,1},{4,1},{4,1},
    {8,0},
    {4,1},
    {1,0},
    {2,1},
};
#define N_TAIL_FIELDS (sizeof(HEADER_TAIL_FIELDS)/sizeof(HEADER_TAIL_FIELDS[0]))
#define IDX_LAYERCOUNT 0
#define IDX_RESX 1
#define IDX_RESY 2
#define IDX_OFFSET_LAYER_CONTENT (N_TAIL_FIELDS-3)
/* Observed in every real v5.1 sample so far regardless of the job's own
 * AntiAliasingLevel - looks like a printer-wide constant, not per-job. */
#define PIXEL_BITWIDTH 3
/* Confirmed 2026-09-03 against a real ChituBox-produced v5.1 file for this
 * exact printer+model - see the full rationale in convert_v3_to_v5 below. */
#define PARTITION_COUNT 2 /* real reference files (SatelLite and ChituBox
    exports alike) both use 2 for this printer's resolution */

static const int LAYERDEF_FIELD_SIZES[] = {
    2, 4,4,4,4,4,4,4,4,4,4,4,4,4,4,4, 2
};
#define N_LAYERDEF_FIELDS (sizeof(LAYERDEF_FIELD_SIZES)/sizeof(int))

static void gflip(uint8_t *p, int size) {
    for (int i = 0; i < size/2; i++) { uint8_t t=p[i]; p[i]=p[size-1-i]; p[size-1-i]=t; }
}

/* --- v3's per-layer RLE codec and v5's "VUF" codec, ported from
 * goo_v3_to_v5.c (see that file for the full rationale/comment - confirmed
 * 2026-09-03 via live printer test + UVtools source that these are two
 * different bitstreams sharing only the same 0x55-magic/checksum wrapper;
 * the original byte-copy approach let headers/tables parse fine while
 * leaving the actual layer image undecodable, so nothing physically
 * printed even though the firmware's timing/layer counter advanced). */
static int gv3_decode_layer(const uint8_t *rle, size_t rle_len,
                             uint32_t width, uint32_t height, uint8_t *out_px) {
    if (rle_len < 3 || rle[0] != 0x55) return -1;
    size_t last = rle_len - 1;
    uint8_t checksum = 0;
    for (size_t i = 1; i < last; i++) checksum = (uint8_t)(checksum + rle[i]);
    checksum = (uint8_t)~checksum;
    if (rle[last] != checksum) return -1;

    size_t total_pixels = (size_t)width * height;
    size_t pixel = 0;
    uint8_t color = 0;
    size_t i = 1;
    while (i < last) {
        uint8_t tag = rle[i];
        uint8_t chunk_type = (uint8_t)(tag >> 6);
        size_t stride = 0;
        size_t s0 = i, s1 = i + 1, s2 = i + 2, s3 = i + 3;

        if (chunk_type == 0x0) {
            color = 0;
        } else if (chunk_type == 0x1) {
            if (i + 1 >= last) return -1;
            color = rle[++i];
            s1++; s2++; s3++;
        } else if (chunk_type == 0x2) {
            uint8_t diff_type = (uint8_t)((tag >> 4) & 0x3);
            uint8_t diff_value = (uint8_t)(tag & 0xF);
            if (diff_type == 0x0) { color = (uint8_t)(color + diff_value); stride = 1; }
            else if (diff_type == 0x1) { if (i+1>=last) return -1; color=(uint8_t)(color+diff_value); stride = rle[++i]; }
            else if (diff_type == 0x2) { color = (uint8_t)(color - diff_value); stride = 1; }
            else { if (i+1>=last) return -1; color=(uint8_t)(color-diff_value); stride = rle[++i]; }
        } else if (chunk_type == 0x3) {
            color = 0xFF;
        } else {
            return -1;
        }

        if (chunk_type != 0x2) {
            uint8_t chunk_len = (uint8_t)((rle[s0] >> 4) & 0x3);
            size_t last_idx = chunk_len==0?s0:chunk_len==1?s1:chunk_len==2?s2:s3;
            if (last_idx >= last) return -1;
            switch (chunk_len) {
                case 0: stride = (size_t)(rle[s0] & 0xF); break;
                case 1: stride = ((size_t)rle[s1] << 4) + (rle[s0] & 0xF); i += 1; break;
                case 2: stride = ((size_t)rle[s1] << 12) + ((size_t)rle[s2] << 4) + (rle[s0] & 0xF); i += 2; break;
                default: stride = ((size_t)rle[s1] << 20) + ((size_t)rle[s2] << 12) + ((size_t)rle[s3] << 4) + (rle[s0] & 0xF); i += 3; break;
            }
        }

        if (stride == 0 || pixel + stride > total_pixels) return -1;
        memset(out_px + pixel, color, stride);
        pixel += stride;
        i++;
    }
    if (pixel != total_pixels) return -1;
    return 0;
}

typedef struct { uint8_t *data; size_t len, cap; } GByteBuf;
static void gbb_push(GByteBuf *b, uint8_t v) {
    if (b->len == b->cap) { b->cap = b->cap ? b->cap * 2 : 4096; b->data = (uint8_t*)realloc(b->data, b->cap); }
    b->data[b->len++] = v;
}
static void gvuf_run_chunk(GByteBuf *out, uint32_t size) {
    while (size > 0) {
        uint32_t enLen;
        if (size <= 0x10) {
            enLen = size;
            gbb_push(out, (uint8_t)(0x40 | (enLen - 1)));
        } else if (size <= 0x1000) {
            enLen = size;
            gbb_push(out, (uint8_t)(0x50 | ((enLen - 1) & 0xF)));
            gbb_push(out, (uint8_t)(((enLen - 1) >> 4) & 0xFF));
        } else if (size <= 0x100000) {
            enLen = size;
            gbb_push(out, (uint8_t)(0x60 | ((enLen - 1) & 0xF)));
            gbb_push(out, (uint8_t)(((enLen - 1) >> 4) & 0xFF));
            gbb_push(out, (uint8_t)(((enLen - 1) >> 12) & 0xFF));
        } else {
            enLen = size < 0x10000000u ? size : 0x10000000u;
            gbb_push(out, (uint8_t)(0x70 | ((enLen - 1) & 0xF)));
            gbb_push(out, (uint8_t)(((enLen - 1) >> 4) & 0xFF));
            gbb_push(out, (uint8_t)(((enLen - 1) >> 12) & 0xFF));
            gbb_push(out, (uint8_t)(((enLen - 1) >> 20) & 0xFF));
        }
        size -= enLen;
    }
}
static void gvuf_diff_chunk(GByteBuf *out, int diff) {
    if (diff == 32) gbb_push(out, 0xA0);
    else gbb_push(out, (uint8_t)(0x80 | (diff + 32)));
}
static void gvuf_grey_chunk(GByteBuf *out, uint32_t run, uint8_t value, uint8_t grayMax) {
    if (run > 8) run = 8;
    if (run <= 7 && value < 7) gbb_push(out, (uint8_t)((run << 3) | value));
    else if (run <= 7 && value == grayMax) gbb_push(out, (uint8_t)((run << 3) | 0x07));
    else { gbb_push(out, (uint8_t)(run - 1)); gbb_push(out, value); }
}
static void gvuf_encode_chunk(GByteBuf *out, uint32_t run, uint8_t value, uint8_t prevValue,
                               uint8_t pixelBw, uint8_t grayMax) {
    int diff = (int)value - (int)prevValue;
    if (diff == 0) { gvuf_run_chunk(out, run); return; }
    if (run == 1 && diff >= -32 && diff <= 32) { gvuf_diff_chunk(out, diff); return; }
    if (run <= 7 && pixelBw <= 3) { gvuf_grey_chunk(out, run, value, grayMax); return; }
    if (diff >= -32 && diff <= 32 && run > 1) {
        gvuf_diff_chunk(out, diff); gvuf_run_chunk(out, run - 1); return;
    }
    if ((value == 0 || value == grayMax) && run <= 7) { gvuf_grey_chunk(out, run, value, grayMax); return; }
    if ((value == 0 || value == grayMax) && run > 7) {
        gvuf_grey_chunk(out, 7, value, grayMax); gvuf_run_chunk(out, run - 7); return;
    }
    { uint32_t head = run < 8 ? run : 8;
      gvuf_grey_chunk(out, head, value, grayMax);
      if (run > head) gvuf_run_chunk(out, run - head); }
}
static uint8_t *gencode_layer_image(const uint8_t *px, size_t n, uint8_t pixelBw, size_t *out_len) {
    GByteBuf vuf; vuf.data = NULL; vuf.len = 0; vuf.cap = 0;
    if (n > 0 && pixelBw > 0 && pixelBw <= 8) {
        uint8_t grayMax = (uint8_t)((1 << pixelBw) - 1);
        uint8_t prevChunkValue = 0;
        uint8_t runValue = (uint8_t)(((uint32_t)px[0] * grayMax + 127) / 255);
        uint32_t run = 0;
        for (size_t pos = 0; pos < n; pos++) {
            uint8_t q = (uint8_t)(((uint32_t)px[pos] * grayMax + 127) / 255);
            if (q == runValue) { run++; continue; }
            gvuf_encode_chunk(&vuf, run, runValue, prevChunkValue, pixelBw, grayMax);
            prevChunkValue = runValue;
            runValue = q;
            run = 1;
        }
        if (run > 0) gvuf_encode_chunk(&vuf, run, runValue, prevChunkValue, pixelBw, grayMax);
    }
    uint8_t *result = (uint8_t*)malloc(vuf.len + 2);
    result[0] = 0x55;
    if (vuf.len) memcpy(result + 1, vuf.data, vuf.len);
    uint8_t checksum = 0;
    for (size_t i = 1; i < vuf.len + 1; i++) checksum = (uint8_t)(checksum + result[i]);
    checksum = (uint8_t)~checksum;
    result[vuf.len + 1] = checksum;
    *out_len = vuf.len + 2;
    free(vuf.data);
    return result;
}

/* VUF decoder, the exact inverse of gencode_layer_image above - ported
 * 2026-09-07 from UVtools' own reference implementation
 * (VufCodec.DecodeInto in GooV5File.cs, github.com/sn4k3/UVtools), not
 * reverse-derived from our own encoder, specifically to avoid subtle
 * self-consistent-but-wrong bugs a hand-reversal could introduce. Used to
 * round-trip a layer image CHITUBOX itself already VUF-encoded (captured
 * via the GetSliceImageCompression hook below) back to raw 8bpp pixels,
 * so it can be re-split into this printer's two partitions without ever
 * touching v3's own, different RLE codec for that layer. */
static int gvuf_decode_layer(const uint8_t *vuf, size_t vuf_len,
                              uint32_t width, uint32_t height, uint8_t pixelBw,
                              uint8_t *out_px) {
    if (vuf_len < 3 || vuf[0] != 0x55) return -1;
    size_t last = vuf_len - 1;
    uint8_t checksum = 0;
    for (size_t i = 1; i < last; i++) checksum = (uint8_t)(checksum + vuf[i]);
    checksum = (uint8_t)~checksum;
    if (vuf[last] != checksum) return -1;
    if (pixelBw == 0 || pixelBw > 8) return -1;

    uint8_t grayMax = (uint8_t)((1u << pixelBw) - 1);
    uint8_t colorLut[256];
    if (grayMax == 0) {
        colorLut[0] = 0;
    } else {
        for (uint32_t v = 0; v <= grayMax; v++)
            colorLut[v] = (uint8_t)(((uint32_t)v * 255 + grayMax / 2) / grayMax);
    }

    size_t total_pixels = (size_t)width * height;
    size_t pixel = 0;
    uint8_t prevValue = 0;
    size_t i = 1;

    while (i < last && pixel < total_pixels) {
        uint8_t tag = vuf[i];
        uint8_t chunkType = (uint8_t)(tag >> 6);

        if (chunkType == 0x01) { /* RUN - repeat prevValue */
            uint8_t opt = (uint8_t)((tag >> 4) & 0x03);
            uint32_t count = tag & 0x0F;
            int shift = 4;
            if (i + opt >= last) return -1;
            for (int s = 0; s < opt; s++) {
                i++;
                count |= ((uint32_t)vuf[i]) << shift;
                shift += 8;
            }
            count += 1;
            if (pixel + count > total_pixels) return -1;
            memset(out_px + pixel, colorLut[prevValue], count);
            pixel += count;
            i++;
        } else if (chunkType == 0x02) { /* DIFF - single pixel, prevValue+diff */
            int diff = (tag == 0xA0) ? 32 : ((int)(tag & 0x3F) - 32);
            int value = (int)prevValue + diff;
            if (value < 0 || value > grayMax) return -1;
            prevValue = (uint8_t)value;
            if (pixel >= total_pixels) return -1;
            out_px[pixel] = colorLut[prevValue];
            pixel += 1;
            i++;
        } else if (chunkType == 0x00) { /* GRAY - explicit value + short run */
            uint8_t countBits = (uint8_t)((tag >> 3) & 0x07);
            uint8_t value;
            uint32_t count;
            if (countBits != 0) {
                count = countBits;
                value = ((tag & 0x07) == 0x07) ? grayMax : (uint8_t)(tag & 0x07);
            } else {
                if (i + 1 >= last) return -1;
                count = (uint32_t)(tag & 0x07) + 1;
                i++;
                value = vuf[i];
            }
            if (value > grayMax) return -1;
            if (pixel + count > total_pixels) return -1;
            memset(out_px + pixel, colorLut[value], count);
            prevValue = value;
            pixel += count;
            i++;
        } else {
            return -1; /* 0x03 - unused chunk type */
        }
    }
    if (pixel != total_pixels) return -1;
    return 0;
}

/* --- Minimal MD5 (RFC 1321), ported from goo_v3_to_v5.c - see that file's
 * comment above md5_rotl for the full rationale. v5 files end with a
 * 64-byte trailer: 30 zero bytes + "\r\n" + 32-char ASCII-hex MD5 of
 * everything before those 32 hex chars. Confirmed live 2026-09-03: the
 * printer's own reported PrintInfo.MD5 for a job matches this exactly. */
static uint32_t gmd5_rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void gmd5_transform(uint32_t state[4], const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = block[i*4] | ((uint32_t)block[i*4+1]<<8) | ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3*i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7*i) % 16; }
        uint32_t temp = D;
        D = C; C = B;
        B = B + gmd5_rotl(A + F + K[i] + M[g], S[i]);
        A = temp;
    }
    state[0] += A; state[1] += B; state[2] += C; state[3] += D;
}

static void gmd5_buffer(const uint8_t *data, size_t len, uint8_t digest[16]) {
    uint32_t state[4] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    uint64_t bitlen = (uint64_t)len * 8;
    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    uint8_t *buf = (uint8_t*)calloc(1, padded_len);
    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) buf[padded_len - 8 + i] = (uint8_t)(bitlen >> (8*i));
    for (size_t off = 0; off < padded_len; off += 64) gmd5_transform(state, buf + off);
    free(buf);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            digest[i*4+j] = (uint8_t)(state[i] >> (8*j));
}

static void gmd5_hex(const uint8_t *data, size_t len, char out_hex[32]) {
    uint8_t d[16];
    gmd5_buffer(data, len, d);
    static const char *hexch = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i*2]   = hexch[d[i] >> 4];
        out_hex[i*2+1] = hexch[d[i] & 0xf];
    }
}

void hooklog(const char *fmt, ...); /* defined below; non-static (external linkage) since
                                        qml_probe.cpp (a separate translation unit, linked
                                        into this same DLL) also calls it - see there. */

/* Per-layer cache of already-VUF-encoded partition blobs, filled by the
 * GetSliceImageCompression hook below as CHITUBOX Pro slices, so the
 * file-conversion path (convert_v3_to_v5) can skip decoding+re-encoding
 * every layer's pixels itself and just reuse this work - the whole point
 * of this hook. See GOO_V3_V5_FORMAT_NOTES.md "2026-09-07" for how this
 * was found and why a plain sequential index is safe here (confirmed
 * live: IsNeedSlicePath() returns false for the goo format specifically,
 * which is what selects CHITUBOX's own strictly-sequential, single-
 * threaded per-layer path - not a per-job decision, so this holds for
 * every goo export regardless of size, not just small test files).
 *
 * g_hookGetSliceActive/layer_cache_reset() exist so a failure anywhere
 * in this path (hook never installed, one layer's decode/encode failing,
 * a layer-count mismatch against the file CHITUBOX actually wrote) falls
 * back to the original, already-proven full-decode conversion instead of
 * ever silently shipping a partially-cached, wrong file. */
typedef struct { uint8_t *part[PARTITION_COUNT]; size_t partLen[PARTITION_COUNT]; } CachedLayer;
static CRITICAL_SECTION g_layerCacheCS;
static CachedLayer *g_layerCache = NULL;
static size_t g_layerCacheCount = 0;
static size_t g_layerCacheCap = 0;
static volatile LONG g_layerIndex = 0;
static volatile LONG g_hookGetSliceActive = 0;
static volatile LONG g_getSliceCallCount; /* tentative def; real init is later, next to
                                              Hook_GetSliceImageCompression - forward-declared
                                              here so convert_v3_to_v5 can log it. */

/* This printer's fixed panel resolution (ELEGOO Jupiter 2 / EL3D-5) - a
 * hardware constant for this profile, not something read per-job. If
 * this hook is ever reused for a different printer/profile with a
 * different resolution, update this (or make it dynamic) - getting it
 * wrong doesn't corrupt anything silently: gv3_decode_layer validates
 * the decoded pixel count strictly and returns failure on any mismatch,
 * which Hook_GetSliceImageCompression already treats as "skip caching
 * this layer, let the normal fallback path handle the whole file". */
#define KNOWN_RES_X 15120
#define KNOWN_RES_Y 6230

static void layer_cache_reset(void) {
    EnterCriticalSection(&g_layerCacheCS);
    for (size_t i = 0; i < g_layerCacheCount; i++) {
        for (int pp = 0; pp < PARTITION_COUNT; pp++) free(g_layerCache[i].part[pp]);
    }
    free(g_layerCache);
    g_layerCache = NULL;
    g_layerCacheCount = 0;
    g_layerCacheCap = 0;
    g_layerIndex = 0;
    g_hookGetSliceActive = 0;
    LeaveCriticalSection(&g_layerCacheCS);
}

/* File-scope (was a local typedef inside convert_v3_to_v5) so the
 * per-thread worker below can take a pointer to this array. Read-only
 * once built - every worker thread only reads it, never writes it, so no
 * synchronization is needed to share it across threads. */
typedef struct { size_t def_off; uint32_t data_size; } LayerInfo;

/* Per-layer decode+re-encode worker (2026-09-07): convert_v3_to_v5's own
 * fallback path (decode this file's v3 RLE, re-encode as VUF) is pure CPU
 * work operating only on the file's own bytes - no CHITUBOX interaction,
 * so unlike the abandoned GetSliceImageCompression hook (see
 * REVERSE_ENGINEERING_HANDOFF.md's 2026-09-07 section for why that one
 * was reverted) there is zero live-process risk in speeding this up.
 * Each layer's decode+encode is fully independent (its own pixel_buf/
 * half_buf scratch space, its own enc_data[idx]/enc_len[idx] output
 * slot) so a contiguous range of layer indices can be handed to each
 * thread with no shared mutable state except the caller-owned enc_data/
 * enc_len arrays themselves - and since every thread writes to disjoint
 * indices (idx = i*partition_count+pp, disjoint i ranges never overlap),
 * that's safe without a lock. */
typedef struct {
    const uint8_t *v3;
    const LayerInfo *layers;
    uint32_t start, end; /* half-open [start, end) range of layer indices */
    uint32_t res_x, res_y;
    uint32_t half_width;
    size_t half_pixel_count;
    int partition_count;
    uint8_t **enc_data;
    size_t *enc_len;
    volatile LONG *failFlag;
} ConvertWorkerArgs;

static DWORD WINAPI convert_worker_thread(LPVOID param) {
    ConvertWorkerArgs *a = (ConvertWorkerArgs*)param;
    size_t pixel_count = (size_t)a->res_x * a->res_y;
    uint8_t *pixel_buf = (uint8_t*)malloc(pixel_count);
    uint8_t *half_buf = (uint8_t*)malloc(a->half_pixel_count);
    if (!pixel_buf || !half_buf) {
        InterlockedExchange(a->failFlag, 1);
        free(pixel_buf); free(half_buf);
        return 0;
    }
    for (uint32_t i = a->start; i < a->end; i++) {
        if (*a->failFlag) break;
        const uint8_t *rle = a->v3 + a->layers[i].def_off + 70;
        if (i == 0) {
            char hex[3*32+1]; hex[0] = 0;
            for (int b = 0; b < 32 && (uint32_t)b < a->layers[i].data_size; b++) { char t[4]; sprintf(t, "%02x ", rle[b]); strcat(hex, t); }
            hooklog("convert_v3_to_v5: FILE layer[0] data_size=%lu bytes[0..31]=%s",
                    (unsigned long)a->layers[i].data_size, hex);
        }
        if (gv3_decode_layer(rle, a->layers[i].data_size, a->res_x, a->res_y, pixel_buf) != 0) {
            InterlockedExchange(a->failFlag, 1);
            break;
        }
        int layerOk = 1;
        for (int pp = 0; pp < a->partition_count; pp++) {
            for (uint32_t row = 0; row < a->res_y; row++) {
                memcpy(half_buf + (size_t)row * a->half_width,
                       pixel_buf + (size_t)row * a->res_x + (size_t)pp * a->half_width,
                       a->half_width);
            }
            size_t idx = (size_t)i * a->partition_count + pp;
            a->enc_data[idx] = gencode_layer_image(half_buf, a->half_pixel_count, PIXEL_BITWIDTH, &a->enc_len[idx]);
            if (!a->enc_data[idx]) layerOk = 0;
        }
        if (!layerOk) { InterlockedExchange(a->failFlag, 1); break; }
    }
    free(pixel_buf);
    free(half_buf);
    return 0;
}

static int convert_v3_to_v5(const uint8_t *v3, size_t v3_len, uint8_t **out_v5, size_t *out_len) {
    if (v3_len < 32 || memcmp(v3, "V3.0", 4) != 0) return -1;

    size_t pos = V3_HEADER_FIXED_STR_SIZE;
    pos += 6; /* AntiAliasingLevel+GreyLevel+BlurLevel, before the previews */
    pos += 116*116*2 + 2;
    pos += 290*290*2 + 2;
    size_t tail_start = pos;

    size_t p = tail_start;
    uint32_t layer_count = 0, offset_layer_content = 0;
    uint16_t res_x = 0, res_y = 0;
    for (size_t i = 0; i < N_TAIL_FIELDS; i++) {
        int sz = HEADER_TAIL_FIELDS[i].size;
        if (i == IDX_LAYERCOUNT) layer_count = gbe32(v3+p);
        if (i == IDX_RESX) res_x = (uint16_t)((v3[p]<<8)|v3[p+1]);
        if (i == IDX_RESY) res_y = (uint16_t)((v3[p]<<8)|v3[p+1]);
        if (i == IDX_OFFSET_LAYER_CONTENT) offset_layer_content = gbe32(v3+p);
        p += sz;
    }
    if (offset_layer_content == 0 || offset_layer_content > v3_len || offset_layer_content != p) return -1;
    if (res_x == 0 || res_y == 0) return -1;

    /* 2026-09-08: this hook now also fires for files own_manager.py asks
     * CHITUBOX to save via its own "Network Sending" TCP protocol (see
     * README/handoff), not just the normal Save Slice folder - meaning it
     * could in principle see a v3 file from a DIFFERENT printer profile
     * too (any model CHITUBOX can slice for). The v5 header/table layout
     * built below (PartitionCount=2, VUF pixel codec, RDT/LDT/IEDT sizes)
     * was reverse-engineered specifically against the ELEGOO Jupiter 2's
     * real panel resolution and is not validated for any other model -
     * converting a different printer's v3 file with it would silently
     * produce a wrong, corrupt file. Hard-require the exact known
     * resolution; anything else is left untouched (v3, unconverted) same
     * as any other unsupported/malformed input. */
    if (res_x != KNOWN_RES_X || res_y != KNOWN_RES_Y) {
        hooklog("convert_v3_to_v5: resolution %ux%u does not match ELEGOO Jupiter 2 (%ux%u) - "
                "not converting (this file is for a different printer)",
                (unsigned)res_x, (unsigned)res_y, (unsigned)KNOWN_RES_X, (unsigned)KNOWN_RES_Y);
        return -1;
    }

    LayerInfo *layers = (LayerInfo*)malloc(sizeof(LayerInfo) * layer_count);
    if (!layers) return -1;

    size_t cur = offset_layer_content;
    for (uint32_t i = 0; i < layer_count; i++) {
        if (cur + 70 > v3_len) { free(layers); return -1; }
        layers[i].def_off = cur;
        uint32_t data_size = gbe32(v3 + cur + 66);
        layers[i].data_size = data_size;
        cur += 66 + 4 + data_size + 2;
    }

    /* Decode each v3-codec layer to raw 8bpp pixels and re-encode with v5's
     * VUF codec - v3's own byte stream is NOT VUF-compatible even though
     * both wrap it in the same 0x55-magic/checksum envelope (confirmed
     * 2026-09-03: UVtools rejected a verbatim-copied file with "VUF GRAY
     * chunk contains an invalid grayscale value", and the printer's own
     * firmware silently produced no light output for the same reason,
     * while headers/tables/timing all still parsed and advanced fine).
     *
     * PARTITION_COUNT=2 confirmed 2026-09-03 by reading a real ChituBox-
     * produced v5.1 file for this exact printer+model: its header has
     * PartitionCount=2 and its LDT/IEDT/RDT addresses only line up if IEDT
     * holds layer_count*2 entries. partition_count=1 (this converter's
     * original choice) parses fine in UVtools' own reader but is not what
     * the real firmware expects - suspected cause of a live-tested symptom
     * where the printer sat in EXPOSURING for 10+ minutes with
     * CurrentTicks stuck at 0. Each partition is a left/right column split
     * of the full-width image, ported from GooV5File's own encoder. */
    if (res_x % PARTITION_COUNT != 0) { free(layers); return -1; }
    const int partition_count = PARTITION_COUNT;
    uint32_t half_width = res_x / PARTITION_COUNT;
    size_t half_pixel_count = (size_t)half_width * res_y;
    uint8_t **enc_data = (uint8_t**)calloc((size_t)layer_count * partition_count, sizeof(uint8_t*));
    size_t *enc_len = (size_t*)calloc((size_t)layer_count * partition_count, sizeof(size_t));
    if (!enc_data || !enc_len) {
        free(layers); free(enc_data); free(enc_len);
        return -1;
    }
    /* Fast path (2026-09-07): if Hook_GetSliceImageCompression already
     * captured every layer's pixels straight from CHITUBOX Pro's own
     * in-memory slice result and pre-encoded them to VUF (see the long
     * comment above that hook), reuse that instead of decoding this
     * file's v3 RLE and re-encoding from scratch - the whole point being
     * to do the actual pixel-level work exactly once. Only trusted when
     * every precondition lines up exactly; any mismatch falls back to
     * the original full-decode path below, which has been live-validated
     * on the real printer since 2026-09-03 and never depends on the hook
     * at all. */
    int use_cache = (g_hookGetSliceActive && g_layerCacheCount == layer_count &&
                      res_x == KNOWN_RES_X && res_y == KNOWN_RES_Y &&
                      partition_count == PARTITION_COUNT);
    hooklog("convert_v3_to_v5: cache check - hookActive=%ld cachedLayers=%zu fileLayers=%lu "
            "resX=%u(known=%u) resY=%u(known=%u) use_cache=%d totalGetSliceCalls=%ld",
            g_hookGetSliceActive, g_layerCacheCount, (unsigned long)layer_count,
            (unsigned)res_x, (unsigned)KNOWN_RES_X, (unsigned)res_y, (unsigned)KNOWN_RES_Y, use_cache,
            g_getSliceCallCount);
    if (use_cache) {
        EnterCriticalSection(&g_layerCacheCS);
        for (uint32_t i = 0; i < layer_count && use_cache; i++) {
            for (int pp = 0; pp < partition_count; pp++) {
                if (!g_layerCache[i].part[pp]) { use_cache = 0; break; }
            }
        }
        if (use_cache) {
            for (uint32_t i = 0; i < layer_count; i++) {
                for (int pp = 0; pp < partition_count; pp++) {
                    size_t idx = (size_t)i * partition_count + pp;
                    enc_len[idx] = g_layerCache[i].partLen[pp];
                    enc_data[idx] = (uint8_t*)malloc(enc_len[idx]);
                    if (!enc_data[idx]) { use_cache = 0; break; }
                    memcpy(enc_data[idx], g_layerCache[i].part[pp], enc_len[idx]);
                }
            }
        }
        LeaveCriticalSection(&g_layerCacheCS);
        if (use_cache) hooklog("convert_v3_to_v5: reusing %lu cached layer(s), skipped decode+re-encode", (unsigned long)layer_count);
        else {
            /* partial allocation failure - clean up and fall through to the normal path */
            for (size_t j = 0; j < (size_t)layer_count * partition_count; j++) { free(enc_data[j]); enc_data[j] = NULL; }
        }
    }
    if (!use_cache) {
        /* Parallelized (2026-09-07): each thread gets a contiguous range of
         * layer indices and its own pixel_buf/half_buf scratch space (see
         * the long comment above convert_worker_thread for why this is
         * safe). Capped at the CPU's real core count (and never more
         * threads than layers) so this scales down cleanly on small jobs
         * and doesn't oversubscribe on large ones. */
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        DWORD numThreads = sysinfo.dwNumberOfProcessors;
        if (numThreads < 1) numThreads = 1;
        if (numThreads > 32) numThreads = 32; /* WaitForMultipleObjects cap is 64; stay well under */
        if (layer_count > 0 && numThreads > layer_count) numThreads = layer_count;
        if (numThreads < 1) numThreads = 1;

        ConvertWorkerArgs *wargs = (ConvertWorkerArgs*)calloc(numThreads, sizeof(ConvertWorkerArgs));
        HANDLE *threadHandles = (HANDLE*)calloc(numThreads, sizeof(HANDLE));
        volatile LONG failFlag = 0;
        if (!wargs || !threadHandles) {
            free(wargs); free(threadHandles);
            for (size_t j = 0; j < (size_t)layer_count * partition_count; j++) free(enc_data[j]);
            free(layers); free(enc_data); free(enc_len);
            return -1;
        }

        ULONGLONG t_start = GetTickCount64();
        uint32_t chunk = (layer_count + numThreads - 1) / numThreads;
        DWORD launched = 0;
        for (DWORD t = 0; t < numThreads; t++) {
            uint32_t start = t * chunk;
            uint32_t end = start + chunk;
            if (end > layer_count) end = layer_count;
            if (start >= end) continue;
            ConvertWorkerArgs *a = &wargs[launched];
            a->v3 = v3; a->layers = layers; a->start = start; a->end = end;
            a->res_x = res_x; a->res_y = res_y; a->half_width = half_width;
            a->half_pixel_count = half_pixel_count; a->partition_count = partition_count;
            a->enc_data = enc_data; a->enc_len = enc_len; a->failFlag = &failFlag;
            threadHandles[launched] = CreateThread(NULL, 0, convert_worker_thread, a, 0, NULL);
            if (threadHandles[launched]) launched++;
            else InterlockedExchange(&failFlag, 1);
        }
        if (launched > 0) WaitForMultipleObjects(launched, threadHandles, TRUE, INFINITE);
        ULONGLONG t_elapsed_ms = GetTickCount64() - t_start;
        for (DWORD t = 0; t < launched; t++) CloseHandle(threadHandles[t]);
        free(threadHandles);
        free(wargs);

        hooklog("convert_v3_to_v5: parallel decode+encode across %lu thread(s) for %lu layer(s), failed=%d, took %llu ms",
                (unsigned long)numThreads, (unsigned long)layer_count, (int)failFlag,
                (unsigned long long)t_elapsed_ms);

        if (failFlag) {
            for (size_t j = 0; j < (size_t)layer_count * partition_count; j++) free(enc_data[j]);
            free(layers); free(enc_data); free(enc_len);
            return -1;
        }
    }

    size_t ldt_size = 1 + (size_t)layer_count * 8;
    size_t iedt_size = 1 + (size_t)layer_count * partition_count * 8;
    /* RDT is an index table (magic+count+offset/size entries), same shape
     * as LDT/IEDT - NOT inline resin data. See goo_v3_to_v5.c's rdt_size
     * comment for how this was found (2026-09-03, reading jup_v5.goo's
     * real RDT entry, which points to a separate ResinDef blob after all
     * layer content: Magic+Name(128)+ResinType(128)+Color(3)+Density(f32)+
     * Stickiness(f32)+Delimiter(2) = 270 bytes). The "lift/retract floats"
     * this converter previously wrote inline here were read from the
     * wrong offset in an earlier session and just coincidentally decoded
     * as plausible-looking numbers. */
    size_t rdt_size = 1 + 4 + 8; /* magic + count(=1) + one index entry */
    size_t resin_blob_size = 1 + 128 + 128 + 3 + 4 + 4 + 2; /* ResinDef, 270 bytes */

    size_t v3_header_total = p;
    size_t v5_header_total = v3_header_total + 1 + 4 + 4 + 4 + 1 + 1;
    size_t new_layer_content_start = v5_header_total + ldt_size + iedt_size + rdt_size;
    /* All LayerDefs first (66 bytes each, contiguous), then all image
     * blocks after (no DataLength prefix) - see the LDT/IEDT-writing
     * comment below: the real reader/firmware isn't purely offset-driven
     * for LayerDefs and expects this exact physical grouping (confirmed
     * 2026-09-03: the vendor slicer showed a garbled model and absurd
     * PositionZ values with the old interleaved layout). */
    size_t content_len = (size_t)layer_count * 66;
    for (uint32_t i = 0; i < layer_count; i++) {
        for (int pp = 0; pp < partition_count; pp++)
            content_len += enc_len[(size_t)i * partition_count + pp] + 2;
    }
    size_t resin_blob_off = new_layer_content_start + content_len;
    size_t trailer_off = resin_blob_off + resin_blob_size;
    size_t v5_len = trailer_off + 64;
    uint8_t *v5 = (uint8_t*)calloc(1, v5_len);
    if (!v5) {
        for (uint32_t j = 0; j < (size_t)layer_count * partition_count; j++) free(enc_data[j]);
        free(layers); free(enc_data); free(enc_len);
        return -1;
    }

    memcpy(v5, v3, tail_start);
    memcpy(v5, "V5.1", 4);

    gflip(v5 + V3_HEADER_FIXED_STR_SIZE, 2);
    gflip(v5 + V3_HEADER_FIXED_STR_SIZE + 2, 2);
    gflip(v5 + V3_HEADER_FIXED_STR_SIZE + 4, 2);

    size_t src_p = tail_start, dst_p = tail_start;
    for (size_t i = 0; i < N_TAIL_FIELDS; i++) {
        int sz = HEADER_TAIL_FIELDS[i].size;
        int numeric = HEADER_TAIL_FIELDS[i].numeric;
        memcpy(v5+dst_p, v3+src_p, sz);
        if (numeric) gflip(v5+dst_p, sz);
        src_p += sz; dst_p += sz;
    }

    v5[dst_p] = (uint8_t)partition_count; dst_p += 1;
    gput_le32(v5+dst_p, (uint32_t)v5_header_total); dst_p += 4;
    gput_le32(v5+dst_p, (uint32_t)(v5_header_total+ldt_size)); dst_p += 4;
    gput_le32(v5+dst_p, (uint32_t)(v5_header_total+ldt_size+iedt_size)); dst_p += 4;
    v5[dst_p] = 0; dst_p += 1;
    v5[dst_p] = PIXEL_BITWIDTH; dst_p += 1;
    if (dst_p != v5_header_total) {
        for (uint32_t j = 0; j < (size_t)layer_count * partition_count; j++) free(enc_data[j]);
        free(layers); free(enc_data); free(enc_len); free(v5); return -1;
    }

    size_t layerdefs_start = new_layer_content_start;
    size_t images_start = layerdefs_start + (size_t)layer_count * 66;

    size_t ldt_off = v5_header_total;
    v5[ldt_off] = 0xA1;
    for (uint32_t i = 0; i < layer_count; i++) {
        gput_le32(v5+ldt_off+1+i*8, (uint32_t)(layerdefs_start + (size_t)i * 66));
        gput_le32(v5+ldt_off+1+i*8+4, 66);
    }

    size_t iedt_off = v5_header_total + ldt_size;
    v5[iedt_off] = 0xA2;
    size_t new_off = images_start;
    for (uint32_t i = 0; i < layer_count; i++) {
        for (int pp = 0; pp < partition_count; pp++) {
            size_t idx = (size_t)i * partition_count + pp;
            size_t entry_pos = iedt_off + 1 + idx * 8;
            gput_le32(v5+entry_pos, (uint32_t)new_off);
            /* Size includes the trailing \r\n, matching the real writer -
             * see goo_v3_to_v5.c's comment for the full story (confirmed
             * 2026-09-03 by diffing a genuine SatelLite file's own IEDT). */
            gput_le32(v5+entry_pos+4, (uint32_t)(enc_len[idx] + 2));
            new_off += enc_len[idx] + 2;
        }
    }

    size_t rdt_off = v5_header_total + ldt_size + iedt_size;
    v5[rdt_off] = 0xA3;
    gput_le32(v5+rdt_off+1, 1);
    gput_le32(v5+rdt_off+5, (uint32_t)resin_blob_off);
    gput_le32(v5+rdt_off+9, (uint32_t)resin_blob_size);
    {
        uint8_t *rb = v5 + resin_blob_off;
        size_t rp = 0;
        rb[rp] = 0x66; rp += 1;
        memset(rb+rp, 0, 128);
        memcpy(rb+rp, "Normal", 6);
        rp += 128;
        memset(rb+rp, 0, 128);
        rp += 128;
        rb[rp]=0x80; rb[rp+1]=0x80; rb[rp+2]=0x80; rp += 3;
        { float density = 1.0f; memcpy(rb+rp, &density, 4); rp += 4; }
        { float stickiness = 0.5f; memcpy(rb+rp, &stickiness, 4); rp += 4; }
        rb[rp] = '\r'; rb[rp+1] = '\n'; rp += 2;
    }

    for (uint32_t i = 0; i < layer_count; i++) {
        size_t s = layers[i].def_off;
        size_t d = layerdefs_start + (size_t)i * 66;
        size_t fp = 0;
        for (size_t fi = 0; fi < N_LAYERDEF_FIELDS; fi++) {
            int sz = LAYERDEF_FIELD_SIZES[fi];
            memcpy(v5+d+fp, v3+s+fp, sz);
            gflip(v5+d+fp, sz);
            fp += sz;
        }
        memcpy(v5+d+fp, v3+s+fp, 66-fp);
    }

    size_t dst_img = images_start;
    for (uint32_t i = 0; i < layer_count; i++) {
        for (int pp = 0; pp < partition_count; pp++) {
            size_t idx = (size_t)i * partition_count + pp;
            memcpy(v5+dst_img, enc_data[idx], enc_len[idx]);
            free(enc_data[idx]);
            v5[dst_img+enc_len[idx]] = '\r';
            v5[dst_img+enc_len[idx]+1] = '\n';
            dst_img += enc_len[idx] + 2;
        }
    }

    free(layers);
    free(enc_data);
    free(enc_len);

    v5[trailer_off + 30] = '\r';
    v5[trailer_off + 31] = '\n';
    char hex[32];
    gmd5_hex(v5, trailer_off + 32, hex);
    memcpy(v5 + trailer_off + 32, hex, 32);

    *out_v5 = v5;
    *out_len = v5_len;
    return 0;
}

/* Convert a wide string to ASCII for logging, avoiding %ls inside our
 * narrow vfprintf-based hooklog() - mixing wide-string args into a narrow
 * printf format is a known trouble spot across CRT implementations, and is
 * suspected of corrupting the stack in this static MinGW build (a real
 * ACCESS_VIOLATION was caught by x64dbg with garbage return addresses that
 * were literally bytes from a wide path string). __declspec(thread) so
 * concurrent DirWatcher threads for different drives don't stomp on it. */
static __declspec(thread) char g_narrow_buf[2048];
static const char* narrow(const wchar_t *w) {
    if (!w) { g_narrow_buf[0] = 0; return g_narrow_buf; }
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, g_narrow_buf, sizeof(g_narrow_buf) - 1, NULL, NULL);
    if (n <= 0) g_narrow_buf[0] = 0;
    return g_narrow_buf;
}

/* ---------- logging (best-effort, to %TEMP%\goo_hook.log) ---------- */
void hooklog(const char *fmt, ...) {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat(path, "goo_hook.log");
    FILE *f = fopen(path, "a");
    if (!f) return;
    /* 2026-09-08: added a timestamp prefix (HH:MM:SS.mmm) so questions
     * like "how long did the UVtoolsCmd conversion actually take?" can be
     * answered directly from the log instead of guessing. */
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

/* ---------- IAT hooking machinery ---------- */

typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);

static CreateFileW_t Real_CreateFileW = NULL;
static CloseHandle_t Real_CloseHandle = NULL;

#define MAX_TRACKED 64
static CRITICAL_SECTION g_cs;
static struct { HANDLE h; wchar_t path[MAX_PATH]; } g_tracked[MAX_TRACKED];
static int g_tracked_n = 0;

static void track_add(HANDLE h, LPCWSTR path) {
    EnterCriticalSection(&g_cs);
    if (g_tracked_n < MAX_TRACKED) {
        g_tracked[g_tracked_n].h = h;
        wcsncpy(g_tracked[g_tracked_n].path, path, MAX_PATH-1);
        g_tracked[g_tracked_n].path[MAX_PATH-1] = 0;
        g_tracked_n++;
    }
    LeaveCriticalSection(&g_cs);
}

static int track_take(HANDLE h, wchar_t *out_path) {
    int found = 0;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_tracked_n; i++) {
        if (g_tracked[i].h == h) {
            wcscpy(out_path, g_tracked[i].path);
            g_tracked[i] = g_tracked[--g_tracked_n];
            found = 1;
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
    return found;
}

static int ends_with_goo(LPCWSTR path) {
    size_t len = wcslen(path);
    if (len < 4) return 0;
    return _wcsicmp(path + len - 4, L".goo") == 0;
}

#define MAX_INFLIGHT 32
static wchar_t g_inflight[MAX_INFLIGHT][MAX_PATH * 2 + 4];
static int g_inflight_n = 0;

static int inflight_try_add(const wchar_t *path) {
    int added = 0;
    EnterCriticalSection(&g_cs);
    int already = 0;
    for (int i = 0; i < g_inflight_n; i++) {
        if (_wcsicmp(g_inflight[i], path) == 0) { already = 1; break; }
    }
    if (!already && g_inflight_n < MAX_INFLIGHT) {
        wcscpy(g_inflight[g_inflight_n], path);
        g_inflight_n++;
        added = 1;
    }
    LeaveCriticalSection(&g_cs);
    return added;
}

static void inflight_remove(const wchar_t *path) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_inflight_n; i++) {
        if (_wcsicmp(g_inflight[i], path) == 0) {
            wcscpy(g_inflight[i], g_inflight[--g_inflight_n]);
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
}

/* Renames a just-converted file in place to prepend "v5_" to its base
 * filename (same directory, same volume - a plain rename, not a copy).
 * Purely cosmetic (2026-09-07: added after real confusion this session
 * over whether a given .goo on disk was still V3 or already-converted
 * V5.1 - both CHITUBOX Pro and a separate, newer CHITUBOX app can write
 * files with the exact same naming pattern into the same watched
 * folder). Best-effort: if the rename fails for any reason (permissions,
 * a file already open elsewhere, etc.) the already-written V5.1 content
 * is left exactly where it is, under its original name - a failed
 * rename never loses or corrupts the conversion itself. */
static void rename_with_v5_prefix(LPCWSTR path) {
    const WCHAR *lastSlash = wcsrchr(path, L'\\');
    const WCHAR *lastSlash2 = wcsrchr(path, L'/');
    if (lastSlash2 && (!lastSlash || lastSlash2 > lastSlash)) lastSlash = lastSlash2;
    size_t dirLen = lastSlash ? (size_t)(lastSlash - path + 1) : 0;
    const WCHAR *fname = path + dirLen;
    if (_wcsnicmp(fname, L"v5_", 3) == 0) return; /* already prefixed - don't double up */
    size_t newLen = dirLen + 3 + wcslen(fname);
    WCHAR *newPath = (WCHAR*)malloc((newLen + 1) * sizeof(WCHAR));
    if (!newPath) return;
    if (dirLen) wcsncpy(newPath, path, dirLen);
    newPath[dirLen] = 0;
    wcscat(newPath, L"v5_");
    wcscat(newPath, fname);
    if (!MoveFileW(path, newPath)) {
        hooklog("rename_with_v5_prefix: MoveFileW failed, err=%lu", GetLastError());
    } else {
        hooklog("rename_with_v5_prefix: renamed to add v5_ prefix");
    }
    free(newPath);
}

/* 2026-09-08: toggle for the v3->v5 conversion itself (separate from
 * FL_IsHookEnabled's own toggle, which only gates the merged
 * model-list-JSON feature) - same flag-file pattern, own file, so
 * chitu_hook_tray.ps1 can expose it as its own independent checkbox
 * ("Convert to GOO v5" - the user specifically wants a toggle here, not a
 * one-shot manual-convert action). Missing file / anything other than a
 * leading '0' means enabled, matching every other toggle in this
 * project. */
#define V5CONVERT_ENABLED_FLAG_PATH L"C:\\ChituHook\\chitu_hook_v5convert.flag"

static BOOL V5_IsConvertEnabled(void) {
    HANDLE h = CreateFileW(V5CONVERT_ENABLED_FLAG_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return TRUE;
    char c = 0; DWORD readN = 0;
    ReadFile(h, &c, 1, &readN, NULL);
    CloseHandle(h);
    return !(readN == 1 && c == '0');
}

/* 2026-09-08: convert_v3_to_v5 (this file's own hand-rolled header/codec
 * writer) is RETIRED from the live conversion path. Root cause found the
 * hard way: a real print of a real ELEGOO-Jupiter-2 job stopped ~35%
 * through with no error, and the converted file's own preview thumbnail
 * (extracted independently via UVtoolsCmd's own `extract` command, not
 * just some viewer) was visibly corrupted - confirmed NOT a display bug,
 * the bytes really are wrong in the file. `memcpy(v5, v3, tail_start)`
 * copies the preview region verbatim, so the bug is almost certainly in
 * this file's own hardcoded offset math (V3_HEADER_FIXED_STR_SIZE + the
 * 116x116/290x290 preview size constants) not matching this specific
 * real job's actual header layout - never fully root-caused, because a
 * much safer fix was available: UVtoolsCmd.exe (the same reference tool
 * this whole project has used to understand the format from the start)
 * has its own, mature, independently-maintained GooV5File writer -
 * converting the SAME source file through it (`convert ... GooV5File ...
 * -v 51`) produced a clean, correct preview and (as far as can be told
 * without another real print) a correct file. convert_v3_to_v5/
 * gv3_decode_layer/gencode_layer_image are left in this file (used by
 * test_vuf_roundtrip.c, and as a reference for the format notes) but are
 * no longer called from the live conversion path - do not resume trusting
 * them for a real conversion without first finding and fixing the actual
 * offset bug that caused this. */
#define UVTOOLSCMD_PATH L"C:\\Program Files\\UVtools\\UVtoolsCmd.exe"

static void process_finished_goo(LPCWSTR path) {
    if (!V5_IsConvertEnabled()) {
        hooklog("process_finished_goo: v3->v5 conversion disabled via tray toggle, skipping");
        return;
    }
    /* Cheap magic-byte check only - no need to read the whole (possibly
     * multi-hundred-MB) file into our own memory anymore now that the
     * actual conversion is an external process operating on the file
     * directly. */
    HANDLE h = Real_CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { hooklog("process_finished_goo: cannot reopen for read"); return; }
    char magic[4] = {0};
    DWORD magicRead = 0;
    BOOL magicOk = ReadFile(h, magic, 4, &magicRead, NULL);
    Real_CloseHandle(h);
    if (!magicOk || magicRead != 4 || memcmp(magic, "V3.0", 4) != 0) {
        return; /* not a v3 file (already v5, or unrelated) - leave untouched */
    }

    /* Build "<dir>\v5_<basename>" directly - UVtoolsCmd writes straight to
     * this final name, no separate rename_with_v5_prefix() pass needed
     * (that function still exists for the merged filelist-hook's own use
     * pattern reference, just not called from here anymore). */
    const WCHAR *lastSlash = wcsrchr(path, L'\\');
    const WCHAR *lastSlash2 = wcsrchr(path, L'/');
    if (lastSlash2 && (!lastSlash || lastSlash2 > lastSlash)) lastSlash = lastSlash2;
    size_t dirLen = lastSlash ? (size_t)(lastSlash - path + 1) : 0;
    const WCHAR *fname = path + dirLen;
    if (_wcsnicmp(fname, L"v5_", 3) == 0) return; /* already converted - shouldn't normally reach here given the magic check, but stay safe */

    WCHAR outPath[MAX_PATH * 2];
    if (dirLen + 3 + wcslen(fname) >= MAX_PATH * 2 - 1) { hooklog("process_finished_goo: path too long for UVtoolsCmd conversion"); return; }
    if (dirLen) wcsncpy(outPath, path, dirLen);
    outPath[dirLen] = 0;
    wcscat(outPath, L"v5_");
    wcscat(outPath, fname);

    WCHAR cmdline[MAX_PATH * 6];
    int n = swprintf(cmdline, MAX_PATH * 6,
                      L"\"%s\" --quiet --no-progress convert \"%s\" GooV5File \"%s\" -v 51",
                      UVTOOLSCMD_PATH, path, outPath);
    if (n < 0) { hooklog("process_finished_goo: cmdline build failed"); return; }

    hooklog("process_finished_goo: launching UVtoolsCmd to convert %S -> %S", path, outPath);

    STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    BOOL started = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!started) {
        hooklog("process_finished_goo: CreateProcessW for UVtoolsCmd failed, gle=%lu", GetLastError());
        return;
    }
    /* Real jobs have taken tens of seconds (a 160MB v3 file took ~28s
     * end to end in testing) - give real headroom for a much larger one. */
    DWORD waitRc = WaitForSingleObject(pi.hProcess, 20 * 60 * 1000); /* 20 min */
    DWORD exitCode = 1;
    if (waitRc == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &exitCode);
    else hooklog("process_finished_goo: UVtoolsCmd wait result=%lu (timeout or error)", waitRc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    /* 2026-09-08: UVtoolsCmd's exit code is NOT a reliable success signal -
     * confirmed live, a run that produced a byte-correct output (verified
     * by extracting and visually checking its preview) still exited with
     * code 1, with no error text and a "Done in Ns" success message. Log
     * it for information only; correctness is judged entirely by the
     * output file actually existing, starting with the right magic, and
     * not being suspiciously truncated (checks below). */
    hooklog("process_finished_goo: UVtoolsCmd exit code=%lu (informational only, not treated as success/failure)", exitCode);

    LARGE_INTEGER inSz; inSz.QuadPart = 0;
    HANDLE ih = Real_CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ih != INVALID_HANDLE_VALUE) { GetFileSizeEx(ih, &inSz); Real_CloseHandle(ih); }

    HANDLE vh = Real_CreateFileW(outPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (vh == INVALID_HANDLE_VALUE) { hooklog("process_finished_goo: output file was not created, conversion failed"); return; }
    char outMagic[4] = {0};
    DWORD outMagicRead = 0;
    ReadFile(vh, outMagic, 4, &outMagicRead, NULL);
    LARGE_INTEGER outSz; outSz.QuadPart = 0;
    GetFileSizeEx(vh, &outSz);
    Real_CloseHandle(vh);
    if (outMagicRead != 4 || memcmp(outMagic, "V5.1", 4) != 0) {
        hooklog("process_finished_goo: output file does not start with V5.1 magic, not trusting it");
        DeleteFileW(outPath);
        return;
    }
    /* Loose sanity floor (10% of input size) against a silently truncated
     * output that still happens to have a valid header - real V5 outputs
     * have always been comparable in magnitude to their V3 input in every
     * case tested (roughly 0.7x-1.8x depending on content), never a tiny
     * fraction of it. */
    if (inSz.QuadPart > 0 && outSz.QuadPart < inSz.QuadPart / 10) {
        hooklog("process_finished_goo: output size (%lld) suspiciously small vs input (%lld), not trusting it",
                outSz.QuadPart, inSz.QuadPart);
        DeleteFileW(outPath);
        return;
    }

    hooklog("process_finished_goo: UVtoolsCmd conversion OK -> %S (%lld -> %lld bytes)", outPath, inSz.QuadPart, outSz.QuadPart);
    DeleteFileW(path); /* the original v3 file - matches the old in-place-overwrite behavior, frees disk space */
}

/* Runs the size-stabilize wait + conversion for one detected .goo path on
 * its OWN thread, off the DirWatcherThread's loop entirely. Confirmed
 * 2026-09-04 on the real setup: with this inline (as it originally was),
 * a single conversion (tens of seconds for a real multi-hundred-layer
 * job) left ReadDirectoryChangesW's kernel-side notification buffer
 * unread for that whole time; the very next call after finishing then
 * failed (observed GetLastError()=183/ERROR_ALREADY_EXISTS - not one of
 * the documented ReadDirectoryChangesW error codes, but reproduced
 * consistently), and the old code treated any such failure as fatal for
 * the thread - so exactly one .goo file per CHITUBOX Pro launch would
 * ever get auto-converted, silently, with no further watching after
 * that. Spawning this off-thread lets the watcher loop return to
 * ReadDirectoryChangesW almost immediately regardless of how long
 * conversion takes, which should avoid triggering whatever this failure
 * mode actually is in the first place - and see reopen-on-failure below
 * for making it non-fatal either way. */
typedef struct { wchar_t path[MAX_PATH * 2 + 4]; } PendingGoo;

static DWORD WINAPI ProcessGooThread(LPVOID arg) {
    PendingGoo *pg = (PendingGoo*)arg;
    LARGE_INTEGER lastSize = {0}, curSize = {0};
    int stableCount = 0;
    for (int tries = 0; tries < 40 && stableCount < 2; tries++) {
        Sleep(250);
        HANDLE h = CreateFileW(pg->path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) { stableCount = 0; continue; }
        GetFileSizeEx(h, &curSize);
        CloseHandle(h);
        if (curSize.QuadPart > 0 && curSize.QuadPart == lastSize.QuadPart) {
            stableCount++;
        } else {
            stableCount = 0;
        }
        lastSize = curSize;
    }
    if (stableCount >= 2) {
        hooklog("Worker: %s stable at %lld bytes, processing", narrow(pg->path), lastSize.QuadPart);
        process_finished_goo(pg->path);
    } else {
        hooklog("Worker: %s never stabilized, skipping", narrow(pg->path));
    }
    inflight_remove(pg->path);
    free(pg);
    return 0;
}

/* Filesystem-watcher fallback: instead of guessing which module's IAT
 * actually issues the CreateFileW/CreateFile2 call for the .goo write
 * (this proved unreliable - neither CHITUBOX Pro.exe's own IAT, nor
 * ucrtbase.dll's, nor librabbit_slice_serial.dll's produced a single hook
 * hit across several real export attempts, meaning the real call path is
 * something else entirely - a Qt file class, a lower-level Nt*File call,
 * or a module not yet identified), watch the filesystem directly for any
 * .goo file being written anywhere under the user's profile, and convert
 * it once its size stops changing (a simple, API-agnostic completion
 * signal that works regardless of which internal path CHITUBOX uses).
 *
 * Self-healing: any ReadDirectoryChangesW failure (or notify-buffer
 * overflow, signaled by ok==TRUE with bytesReturned==0) now just closes
 * and reopens the directory handle and keeps watching, instead of
 * exiting the thread permanently - confirmed live 2026-09-04 that a
 * single conversion's worth of blocking was enough to kill the old
 * one-shot version of this loop. */
static DWORD WINAPI DirWatcherThread(LPVOID arg) {
    wchar_t watchDir[MAX_PATH];
    wcsncpy(watchDir, (const wchar_t*)arg, MAX_PATH - 1);
    watchDir[MAX_PATH - 1] = 0;
    free(arg);

    BYTE *buf = (BYTE*)malloc(64 * 1024);

    for (;;) { /* outer reconnect loop */
        HANDLE hDir = CreateFileW(watchDir, FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hDir == INVALID_HANDLE_VALUE) {
            hooklog("DirWatcher: cannot open %s (err=%lu), retrying in 5s", narrow(watchDir), GetLastError());
            Sleep(5000);
            continue;
        }
        hooklog("DirWatcher: watching %s recursively for .goo files", narrow(watchDir));

        for (;;) { /* inner read-changes loop */
            DWORD bytesReturned = 0;
            BOOL ok = ReadDirectoryChangesW(hDir, buf, 64 * 1024, TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                &bytesReturned, NULL, NULL);
            if (!ok) {
                hooklog("DirWatcher: ReadDirectoryChangesW failed on %s (err=%lu), reopening handle",
                        narrow(watchDir), GetLastError());
                break; /* reopen hDir via the outer loop */
            }
            if (bytesReturned == 0) {
                /* notify buffer overflowed - some changes were missed,
                 * but the handle itself is still fine, keep watching */
                hooklog("DirWatcher: notification buffer overflow on %s, continuing", narrow(watchDir));
                continue;
            }
            BYTE *p = buf;
            for (;;) {
                FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION*)p;
                wchar_t name[MAX_PATH];
                int nlen = info->FileNameLength / 2;
                if (nlen >= MAX_PATH) nlen = MAX_PATH - 1;
                memcpy(name, info->FileName, (size_t)nlen * 2);
                name[nlen] = 0;

                if ((info->Action == FILE_ACTION_MODIFIED || info->Action == FILE_ACTION_ADDED ||
                     info->Action == FILE_ACTION_RENAMED_NEW_NAME) && ends_with_goo(name)) {
                    PendingGoo *pg = (PendingGoo*)malloc(sizeof(PendingGoo));
                    pg->path[0] = 0;
                    wcsncat(pg->path, watchDir, MAX_PATH);
                    size_t wl = wcslen(pg->path);
                    if (wl == 0 || pg->path[wl-1] != L'\\') wcsncat(pg->path, L"\\", 2);
                    wcsncat(pg->path, name, MAX_PATH);
                    if (inflight_try_add(pg->path)) {
                        hooklog("DirWatcher: activity on %s, handing off to worker thread", narrow(pg->path));
                        CreateThread(NULL, 0, ProcessGooThread, pg, 0, NULL);
                    } else {
                        free(pg);
                    }
                }

                if (info->NextEntryOffset == 0) break;
                p += info->NextEntryOffset;
            }
        }
        CloseHandle(hDir);
        Sleep(500); /* brief backoff before reopening, avoid a tight spin on a persistent failure */
    }

    free(buf); /* unreachable (outer loop never exits), kept for clarity */
    return 0;
}

static HANDLE WINAPI Hook_CreateFileW(LPCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                       DWORD disp, DWORD flags, HANDLE tmpl) {
    HANDLE h = Real_CreateFileW(path, access, share, sa, disp, flags, tmpl);
    if (h != INVALID_HANDLE_VALUE && (access & GENERIC_WRITE) && ends_with_goo(path)) {
        track_add(h, path);
        hooklog("tracking .goo write handle for %s", narrow(path));
    }
    return h;
}

static BOOL WINAPI Hook_CloseHandle(HANDLE h) {
    wchar_t path[MAX_PATH];
    int tracked = track_take(h, path);
    BOOL ok = Real_CloseHandle(h);
    if (tracked) {
        process_finished_goo(path);
    }
    return ok;
}

typedef bool (*IsNeedSlicePath_t)(void*);
typedef void (*GetSliceImageCompression_t)(void*, void*);
static IsNeedSlicePath_t Real_IsNeedSlicePath = NULL;
static GetSliceImageCompression_t Real_GetSliceImageCompression = NULL;

/* Called exactly once per export, right before CHITUBOX Pro processes
 * any layer (confirmed live 2026-09-07 via cdb - fires once, ahead of
 * the per-layer loop, its return value picking sequential-vs-thread-pool
 * dispatch for whichever format is active). We don't care about that
 * choice here (goo's own concrete implementation was confirmed live to
 * always return false, i.e. always sequential) - we only use this call
 * as a reliable "a new export just started" signal to reset the layer
 * cache below, so indices from a previous export can never bleed into
 * a new one. Passes the real return value through unchanged either way. */
static bool WINAPI Hook_IsNeedSlicePath(void *thisPtr) {
    layer_cache_reset();
    return Real_IsNeedSlicePath(thisPtr);
}

/* algo::SliceResult::GetSliceImageCompression copies one layer's already-
 * fully-encoded image into the caller's XImage (it's a plain getter, not
 * a compute step - see GOO_V3_V5_FORMAT_NOTES.md "2026-09-07"). Layout
 * confirmed live: XImage+8 holds a pointer to [4-byte big-endian length]
 * [0x55-magic RLE envelope ... one's-complement checksum] - the exact
 * same envelope shape v3's own per-layer codec uses in the file, just
 * with v3's specific RLE grammar inside it (confirmed: gv3_decode_layer
 * successfully decodes it). Decoding it here and re-encoding to VUF
 * (already split into this printer's two partitions) lets
 * convert_v3_to_v5 skip straight to header/table rebuilding for every
 * layer it finds cached, instead of repeating this exact decode+encode
 * pass a second time from the finished file. Never modifies CHITUBOX's
 * own buffer or behavior - purely observes and caches on the side, so a
 * bug here can only ever fail to help, never corrupt what CHITUBOX itself
 * writes. */
static volatile LONG g_getSliceCallCount = 0;

/* 2026-09-07 diagnostic: dump the first few AND last few calls (hardcoded
 * around the known 667-layer test model, with slack past 667 in case of
 * extra/duplicate calls) - so we can tell whether early layers alone look
 * like uninitialized/placeholder buffers, or whether ALL layers do. */
#define DIAG_DUMP_THIS_CALL(n) ((n) <= 3 || ((n) >= 663 && (n) <= 680))

static void Hook_GetSliceImageCompression(void *thisPtr, void *outImage) {
    LONG callNo = InterlockedIncrement(&g_getSliceCallCount);
    if (DIAG_DUMP_THIS_CALL(callNo)) hooklog("Hook_GetSliceImageCompression: ENTRY call #%ld thisPtr=%p outImage=%p", callNo, thisPtr, outImage);

    Real_GetSliceImageCompression(thisPtr, outImage);

    if (DIAG_DUMP_THIS_CALL(callNo)) {
        /* Dump the whole XImage struct's first 96 bytes (SEH-guarded: this
         * memory is real and owned by CHITUBOX, but we're guessing at its
         * layout, so a wrong read must not crash the host process). */
        __try {
            uint8_t *raw = (uint8_t*)outImage;
            char hex[3*96+1]; hex[0] = 0;
            for (int b = 0; b < 96; b++) { char t[4]; sprintf(t, "%02x ", raw[b]); strcat(hex, t); }
            hooklog("Hook_GetSliceImageCompression: call #%ld outImage struct[0..95]=%s", callNo, hex);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            hooklog("Hook_GetSliceImageCompression: call #%ld outImage struct dump FAULTED", callNo);
        }
        /* Heuristic scan: at every 8-byte-aligned offset 0..88 inside the
         * XImage struct, treat the 8 bytes there as a candidate pointer; if
         * it looks like a plausible heap pointer, follow it and check
         * whether byte+4 == 0x55 (our known real per-layer RLE magic, cross-
         * validated against the file's own layer[0] data this same run). */
        __try {
            for (int off = 0; off <= 88; off += 8) {
                uint8_t *candidate = *(uint8_t **)((char *)outImage + off);
                uintptr_t p = (uintptr_t)candidate;
                if (p < 0x10000 || p > 0x00007fffffffffffULL) continue;
                __try {
                    uint32_t lenBE = gbe32(candidate);
                    uint8_t magicByte = candidate[4];
                    if (magicByte == 0x55 && lenBE > 2 && lenBE < 0x1000000u) {
                        hooklog("Hook_GetSliceImageCompression: call #%ld CANDIDATE at struct-offset %d: ptr=%p lenBE=%lu magic=0x55 MATCH",
                                callNo, off, candidate, (unsigned long)lenBE);
                    } else {
                        hooklog("Hook_GetSliceImageCompression: call #%ld struct-offset %d: ptr=%p first8=%02x %02x %02x %02x %02x %02x %02x %02x",
                                callNo, off, candidate,
                                candidate[0], candidate[1], candidate[2], candidate[3],
                                candidate[4], candidate[5], candidate[6], candidate[7]);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    hooklog("Hook_GetSliceImageCompression: call #%ld struct-offset %d: ptr=%p UNREADABLE", callNo, off, candidate);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            hooklog("Hook_GetSliceImageCompression: call #%ld pointer scan FAULTED", callNo);
        }
    }

    uint8_t *buf = *(uint8_t **)((char *)outImage + 8);
    uintptr_t structDataSize = *(uintptr_t *)((char *)outImage + 16);
    if (DIAG_DUMP_THIS_CALL(callNo)) hooklog("Hook_GetSliceImageCompression: call #%ld buf=%p structDataSize(off16)=%zu", callNo, buf, (size_t)structDataSize);
    if (buf == NULL) return;
    uint32_t storedLen = gbe32(buf);
    if (DIAG_DUMP_THIS_CALL(callNo)) {
        /* Scan a bounded window for the first few occurrences of 0x55 (our
         * known real per-layer RLE magic byte, cross-validated against the
         * file's own layer[0] data this same run) - in case the real
         * envelope starts later than buf+4, behind some fixed preamble. */
        __try {
            size_t scanLimit = (structDataSize > 0 && structDataSize < 65536) ? structDataSize : 4096;
            int found = 0;
            for (size_t off = 0; off < scanLimit && found < 5; off++) {
                if (buf[off] == 0x55) {
                    hooklog("Hook_GetSliceImageCompression: call #%ld 0x55 FOUND at buf offset %zu", callNo, off);
                    found++;
                }
            }
            if (!found) hooklog("Hook_GetSliceImageCompression: call #%ld 0x55 NOT FOUND in first %zu bytes of buf", callNo, scanLimit);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            hooklog("Hook_GetSliceImageCompression: call #%ld 0x55 scan FAULTED", callNo);
        }
        char hex[3*24+1]; hex[0] = 0;
        for (int b = 0; b < 24; b++) { char t[4]; sprintf(t, "%02x ", buf[b]); strcat(hex, t); }
        hooklog("Hook_GetSliceImageCompression: call #%ld storedLen=%lu bytes[0..23]=%s", callNo, (unsigned long)storedLen, hex);
        /* also dump the tail near where the checksum should be, using storedLen as-is */
        if (storedLen >= 8 && storedLen < 0x10000000u) {
            uint8_t *tailBase = buf + 4 + storedLen - 8;
            char tailhex[3*8+1]; tailhex[0] = 0;
            for (int b = 0; b < 8; b++) { char t[4]; sprintf(t, "%02x ", tailBase[b]); strcat(tailhex, t); }
            hooklog("Hook_GetSliceImageCompression: call #%ld tail(buf+4+storedLen-8..)=%s", callNo, tailhex);
        }
    }
    if (storedLen < 3 || storedLen > 0x10000000u) return;
    uint8_t *envelope = buf + 4;
    if (envelope[0] != 0x55) return;

    uint8_t *pixel_buf = (uint8_t *)malloc((size_t)KNOWN_RES_X * KNOWN_RES_Y);
    if (!pixel_buf) return;
    int rc = gv3_decode_layer(envelope, storedLen, KNOWN_RES_X, KNOWN_RES_Y, pixel_buf);
    if (rc != 0) {
        free(pixel_buf);
        hooklog("Hook_GetSliceImageCompression: v3 decode failed (rc=%d), skipping cache for this layer", rc);
        return;
    }

    uint32_t half_width = KNOWN_RES_X / PARTITION_COUNT;
    size_t half_pixel_count = (size_t)half_width * KNOWN_RES_Y;
    uint8_t *half_buf = (uint8_t *)malloc(half_pixel_count);
    if (!half_buf) { free(pixel_buf); return; }

    CachedLayer entry;
    memset(&entry, 0, sizeof(entry));
    int ok = 1;
    for (int pp = 0; pp < PARTITION_COUNT; pp++) {
        for (uint32_t row = 0; row < KNOWN_RES_Y; row++) {
            memcpy(half_buf + (size_t)row * half_width,
                   pixel_buf + (size_t)row * KNOWN_RES_X + (size_t)pp * half_width,
                   half_width);
        }
        entry.part[pp] = gencode_layer_image(half_buf, half_pixel_count, PIXEL_BITWIDTH, &entry.partLen[pp]);
        if (!entry.part[pp]) ok = 0;
    }
    free(half_buf);
    free(pixel_buf);

    if (!ok) {
        for (int pp = 0; pp < PARTITION_COUNT; pp++) free(entry.part[pp]);
        hooklog("Hook_GetSliceImageCompression: VUF encode failed, skipping cache for this layer");
        return;
    }

    LONG idx = InterlockedIncrement(&g_layerIndex) - 1;
    EnterCriticalSection(&g_layerCacheCS);
    if ((size_t)idx >= g_layerCacheCap) {
        size_t newCap = g_layerCacheCap ? g_layerCacheCap * 2 : 1024;
        while (newCap <= (size_t)idx) newCap *= 2;
        CachedLayer *grown = (CachedLayer *)realloc(g_layerCache, newCap * sizeof(CachedLayer));
        if (grown) {
            memset(grown + g_layerCacheCap, 0, (newCap - g_layerCacheCap) * sizeof(CachedLayer));
            g_layerCache = grown;
            g_layerCacheCap = newCap;
        }
    }
    if ((size_t)idx < g_layerCacheCap) {
        g_layerCache[idx] = entry;
        if ((size_t)idx + 1 > g_layerCacheCount) g_layerCacheCount = (size_t)idx + 1;
        g_hookGetSliceActive = 1;
        if (idx == 0 || idx < 3) hooklog("Hook_GetSliceImageCompression: cached layer idx=%ld", idx);
    } else {
        for (int pp = 0; pp < PARTITION_COUNT; pp++) free(entry.part[pp]);
    }
    LeaveCriticalSection(&g_layerCacheCS);
}

/* Patches CHITUBOX_Pro.exe's OWN import table for one specific import
 * (matched by exact source-DLL name + exact, already-demangled export
 * name string), redirecting it to `hook`. Deliberately much narrower
 * than patch_iat_everywhere below: GetSliceImageCompression/
 * IsNeedSlicePath are imported by the main EXE specifically (confirmed
 * live via call-stack capture, not guessed), so there's no need to scan
 * other modules at all - just the current process's own main module,
 * gotten directly via GetModuleHandle(NULL) rather than a
 * CreateToolhelp32Snapshot scan. */
static void patch_exe_iat_for_import(const char *dllName, const char *exportName, void *hook, void **out_original) {
    HMODULE exeBase = GetModuleHandleA(NULL);
    if (!exeBase) return;
    BYTE *base = (BYTE*)exeBase;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return;
    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name; imp++) {
        const char *curDllName = (const char*)(base + imp->Name);
        if (_stricmp(curDllName, dllName) != 0) continue;
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA *origThunk = imp->OriginalFirstThunk ?
            (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk) : thunk;
        for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME *byName = (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
            if (strcmp((const char*)byName->Name, exportName) != 0) continue;
            void **slot = (void**)&thunk->u1.Function;
            DWORD oldProt;
            if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
                if (*out_original == NULL) *out_original = *slot;
                *slot = hook;
                VirtualProtect(slot, sizeof(void*), oldProt, &oldProt);
                hooklog("patched exe IAT: %s!%s", dllName, exportName);
            }
        }
    }
}

/* Patch every IAT entry across all loaded modules that imports `name` from
 * kernel32.dll, redirecting it to `hook`, and capture the FIRST original
 * pointer seen into *out_original (they should all be the same value). */
/* Only patch the IAT of a small, curated set of modules known to actually
 * make the file-write calls (std::ofstream/CRT file I/O bottoms out in
 * ucrtbase.dll, not in librabbit_*.dll or any of the Chromium/Qt modules),
 * plus the main EXE as a fallback. Scanning *every* loaded module (as a
 * first version of this did) crashed partway through CHITUBOX Pro's ~400+
 * modules - Chromium/Qt bundles include DLLs with unusual loader setups
 * that this simple PE parser can't safely handle without real SEH (which
 * MinGW doesn't support). Restricting the target list avoids that surface
 * entirely and is sufficient for what we actually need to intercept. */
static int should_scan_module(const char *name) {
    return _stricmp(name, "ucrtbase.dll") == 0 ||
           _stricmp(name, "CHITUBOX Pro.exe") == 0 ||
           _stricmp(name, "msvcp140.dll") == 0 ||
           _stricmp(name, "librabbit_slice_serial.dll") == 0 ||
           _stricmp(name, "librabbit_algorithm.dll") == 0 ||
           _stricmp(name, "librabbit_framework.dll") == 0;
}

static void patch_iat_everywhere(const char *name, void *hook, void **out_original) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (!Module32First(snap, &me)) { CloseHandle(snap); return; }
    do {
        if (!should_scan_module(me.szModule)) continue;
        hooklog("  scanning module %s", me.szModule);
        HMODULE mod = me.hModule;
        BYTE *base = (BYTE*)mod;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(base, &mbi, sizeof(mbi)) == 0) continue;
        if (mbi.State != MEM_COMMIT) continue;

        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 4096) continue; /* sanity bound */
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) continue; /* only x64 PE */
        IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.VirtualAddress > 0x40000000) continue;
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
        for (; imp->Name; imp++) {
            if (imp->Name > 0x40000000) break; /* corrupt/unmapped, bail this module */
            const char *dllName = (const char*)(base + imp->Name);
            if (_stricmp(dllName, "kernel32.dll") != 0 &&
                _stricmp(dllName, "KERNELBASE.dll") != 0) continue;
            IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
            IMAGE_THUNK_DATA *origThunk = imp->OriginalFirstThunk ?
                (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk) : thunk;
            for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
                if (origThunk->u1.AddressOfData > 0x40000000) break;
                IMAGE_IMPORT_BY_NAME *byName = (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
                if (strcmp((const char*)byName->Name, name) != 0) continue;
                void **slot = (void**)&thunk->u1.Function;
                DWORD oldProt;
                if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
                    if (*out_original == NULL) *out_original = *slot;
                    *slot = hook;
                    VirtualProtect(slot, sizeof(void*), oldProt, &oldProt);
                }
            }
        }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
}

/* CHITUBOX Pro.exe is compiled with Control Flow Guard (/guard:cf).
 * Confirmed via Windows Event Log: every crash after IAT-patching showed
 * exception code 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN, the NTSTATUS
 * __fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE) uses) - i.e. CFG
 * rejecting the indirect call through our patched IAT slot because our
 * hook function's address was never registered as a valid ICall target at
 * link time. Register it explicitly before patching anything. Requires
 * Windows 10+; loaded dynamically since older SDKs/headers may lack the
 * declaration and we don't want a hard link-time dependency. */
typedef struct { ULONG Offset; ULONG Flags; } CFG_CALL_TARGET_INFO_MIN;
typedef BOOL (WINAPI *SetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, CFG_CALL_TARGET_INFO_MIN*);
#define CFG_CALL_TARGET_VALID 0x1

static void register_cfg_valid_target(void *fn) {
    SetProcessValidCallTargets_t pSetValid = NULL;
    const char *found_in = NULL;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        pSetValid = (SetProcessValidCallTargets_t)GetProcAddress(k32, "SetProcessValidCallTargets");
        if (pSetValid) found_in = "kernel32.dll";
    }
    if (!pSetValid) {
        HMODULE kb = GetModuleHandleA("kernelbase.dll");
        if (!kb) kb = LoadLibraryA("kernelbase.dll");
        if (kb) {
            pSetValid = (SetProcessValidCallTargets_t)GetProcAddress(kb, "SetProcessValidCallTargets");
            if (pSetValid) found_in = "kernelbase.dll";
        }
    }
    if (!pSetValid) {
        hooklog("SetProcessValidCallTargets not found in kernel32.dll or kernelbase.dll");
        return;
    }
    hooklog("SetProcessValidCallTargets resolved from %s", found_in);

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(fn, &mbi, sizeof(mbi))) { hooklog("VirtualQuery on hook fn failed"); return; }

    CFG_CALL_TARGET_INFO_MIN target;
    target.Offset = (ULONG)((BYTE*)fn - (BYTE*)mbi.BaseAddress);
    target.Flags = CFG_CALL_TARGET_VALID;

    BOOL ok = pSetValid(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, 1, &target);
    hooklog("SetProcessValidCallTargets(fn=%p base=%p size=%zu) -> %d (err=%lu)",
            fn, mbi.BaseAddress, (size_t)mbi.RegionSize, ok, ok ? 0 : GetLastError());
}

/* =====================================================================
 * Filelist hook (2026-09-08): merged in from the separate ChituHook
 * project (C:\ChituHook\chitu_filelist_hook_pro.c) so it loads through
 * this DLL's own already-proven static-import mechanism instead of
 * ChituHook's own separate runtime CreateRemoteThread+LoadLibraryA
 * watcher/scheduled-task - one DLL, one always-on installation path, no
 * risk of the two injection mechanisms interacting badly. Everything in
 * this FL_ (FileList) section is a straight port, offsets and all - see
 * chitu_filelist_hook_pro.c's own header comment for how they were
 * derived (Ghidra + live cdb, specific to this exact CHITUBOX Pro.exe
 * build, the same one all of this file's own RVAs already target).
 *
 * What it does: inline-patches the real CutSlicePageManager::saveSliceFile
 * entry point; on every save, re-fetches the project's full model list via
 * the same UI-internal vtable chain the app itself uses, and writes a
 * plain JSON array of the original (pre-import) model filenames next to
 * the saved file, same base name with a ".json" extension.
 *
 * Toggled by the SAME C:\ChituHook\chitu_hook_enabled.flag file
 * chitu_hook_tray.ps1's existing tray checkbox already writes to - no
 * change needed there for the toggle to keep working. Diagnostics for
 * hook-install specifically go to chitu_hook_debug.log (matching
 * ChituHook's own existing log path), not goo_hook.log, so a machine that
 * already has both logs configured/watched doesn't need to change either.
 * ===================================================================== */

#define FL_RVA_SAVESLICE      0x42d160
#define FL_RVA_GET_CTX        0x268de0
#define FL_OFF_CTX_TO_A       0x20
#define FL_OFF_A_TO_MGR       0x9d8
#define FL_VTBL_SLOT_GETALL   16
#define FL_PROLOGUE_LEN       19
#define FL_DEBUG_LOG_PATH     L"C:\\ChituHook\\chitu_hook_debug.log"
#define FL_ENABLED_FLAG_PATH  L"C:\\ChituHook\\chitu_hook_enabled.flag"

typedef void*             (*FL_GetCtxFn)(void);
typedef void               (*FL_VecCtorFn)(void*);
typedef void               (*FL_VecDtorFn)(void*);
typedef unsigned __int64   (*FL_VecSizeFn)(void*);
typedef void*              (*FL_VecAtFn)(void*, unsigned __int64);
typedef const char*        (*FL_ModelNameFn)(void*);
typedef void                (*FL_GetAllFn)(void*, void*, int);
typedef unsigned __int64   (*FL_SaveSliceFn)(void*, void*, void*);

static FL_VecCtorFn   fl_pVecCtor;
static FL_VecDtorFn   fl_pVecDtor;
static FL_VecSizeFn   fl_pVecSize;
static FL_VecAtFn     fl_pVecAt;
static FL_ModelNameFn fl_pModelName;
static void*          fl_hookAddr;
static void*          fl_trampoline;
static FL_SaveSliceFn fl_pOrigTrampoline;
static CRITICAL_SECTION fl_lock;

#pragma pack(push, 1)
typedef struct { void* d; unsigned short* ptr; long long size; } FL_QStringLayout;
#pragma pack(pop)

static void FL_DebugLog(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)sizeof(buf) - 1;
    EnterCriticalSection(&fl_lock);
    HANDLE h = CreateFileW(FL_DEBUG_LOG_PATH, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD written;
        WriteFile(h, buf, (DWORD)n, &written, NULL);
        WriteFile(h, "\r\n", 2, &written, NULL);
        CloseHandle(h);
    }
    LeaveCriticalSection(&fl_lock);
}

typedef struct { char* data; size_t len; size_t cap; } FL_StrBuf;

static void FL_SbInit(FL_StrBuf* sb) {
    sb->cap = 256; sb->len = 0;
    sb->data = (char*)malloc(sb->cap);
    if (sb->data) sb->data[0] = 0;
}
static void FL_SbFree(FL_StrBuf* sb) {
    if (sb->data) free(sb->data);
    sb->data = NULL; sb->len = sb->cap = 0;
}
static void FL_SbEnsure(FL_StrBuf* sb, size_t extra) {
    if (!sb->data) return;
    if (sb->len + extra + 1 > sb->cap) {
        size_t newCap = sb->cap ? sb->cap * 2 : 256;
        while (newCap < sb->len + extra + 1) newCap *= 2;
        char* nd = (char*)realloc(sb->data, newCap);
        if (nd) { sb->data = nd; sb->cap = newCap; }
    }
}
static void FL_SbAppendN(FL_StrBuf* sb, const char* s, size_t n) {
    if (!sb->data) return;
    FL_SbEnsure(sb, n);
    if (sb->len + n + 1 > sb->cap) return;
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = 0;
}
static void FL_SbAppend(FL_StrBuf* sb, const char* s) { FL_SbAppendN(sb, s, strlen(s)); }

static void FL_SbAppendJsonEscaped(FL_StrBuf* sb, const char* s, size_t n) {
    char tmp[8];
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  FL_SbAppend(sb, "\\\""); break;
            case '\\': FL_SbAppend(sb, "\\\\"); break;
            case '\n': FL_SbAppend(sb, "\\n"); break;
            case '\r': FL_SbAppend(sb, "\\r"); break;
            case '\t': FL_SbAppend(sb, "\\t"); break;
            default:
                if (c < 0x20) {
                    _snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                    FL_SbAppend(sb, tmp);
                } else {
                    FL_SbAppendN(sb, (const char*)&c, 1);
                }
        }
    }
}

/* CHITUBOX Pro appends " #<N>" to algo::ModelAbstract::Name() when the same
 * file is imported more than once (e.g. "foo.stl #2") - strip that back off
 * so the JSON has the plain original filename. */
static size_t FL_EffectiveNameLen(const char* name) {
    size_t len = strlen(name);
    size_t i = len;
    while (i > 0 && name[i - 1] >= '0' && name[i - 1] <= '9') i--;
    if (i == len) return len;
    if (i >= 2 && name[i - 1] == '#' && name[i - 2] == ' ') return i - 2;
    return len;
}
static void FL_SbAppendJsonStringDeduped(FL_StrBuf* sb, const char* s) {
    FL_SbAppend(sb, "\"");
    if (s) FL_SbAppendJsonEscaped(sb, s, FL_EffectiveNameLen(s));
    FL_SbAppend(sb, "\"");
}

/* qsPtr/qsLen: UTF-16 code units of the QString save path (not necessarily
 * null-terminated). Returns a heap-allocated, null-terminated wide string
 * with the extension replaced by ".json", or NULL on failure. */
static wchar_t* FL_DeriveJsonPath(const unsigned short* qsPtr, long long qsLen) {
    if (!qsPtr || qsLen <= 0 || qsLen > 32760) return NULL;
    wchar_t* buf = (wchar_t*)malloc((size_t)(qsLen + 8) * sizeof(wchar_t));
    if (!buf) return NULL;
    memcpy(buf, qsPtr, (size_t)qsLen * sizeof(wchar_t));
    buf[qsLen] = 0;
    long long lastSep = -1, lastDot = -1;
    for (long long i = 0; i < qsLen; i++) {
        if (buf[i] == L'\\' || buf[i] == L'/') lastSep = i;
        if (buf[i] == L'.') lastDot = i;
    }
    long long cutAt = (lastDot > lastSep) ? lastDot : qsLen;
    const wchar_t* ext = L".json";
    memcpy(buf + cutAt, ext, 6 * sizeof(wchar_t)); /* includes NUL */
    return buf;
}

static void FL_WriteWholeFileW(const wchar_t* path, const char* content, size_t len) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { FL_DebugLog("!! could not create output json, gle=%lu", GetLastError()); return; }
    DWORD written;
    WriteFile(h, content, (DWORD)len, &written, NULL);
    CloseHandle(h);
}

/* Re-read on every save so the tray toggle takes effect immediately, no
 * relaunch needed. Missing file / anything other than a leading '0' means
 * enabled (matches chitu_hook_tray.ps1's own default). */
static BOOL FL_IsHookEnabled(void) {
    HANDLE h = CreateFileW(FL_ENABLED_FLAG_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return TRUE;
    char c = 0; DWORD readN = 0;
    ReadFile(h, &c, 1, &readN, NULL);
    CloseHandle(h);
    return !(readN == 1 && c == '0');
}

static unsigned __int64 FL_HookedSaveSlice(void* param1, void* param2, void* param3) {
    __try {
        if (!FL_IsHookEnabled()) __leave;

        wchar_t* jsonPath = NULL;
        if (param2) {
            FL_QStringLayout* qs = (FL_QStringLayout*)param2;
            jsonPath = FL_DeriveJsonPath(qs->ptr, qs->size);
        }

        if (jsonPath && fl_pVecCtor && fl_pVecDtor && fl_pVecSize && fl_pVecAt && fl_pModelName) {
            FL_StrBuf sb;
            FL_SbInit(&sb);
            FL_SbAppend(&sb, "[");

            char* exeBase = (char*)GetModuleHandleA(NULL);
            FL_GetCtxFn getCtx = (FL_GetCtxFn)(exeBase + FL_RVA_GET_CTX);
            void* ctx = getCtx();
            if (ctx) {
                void* a = *(void**)((char*)ctx + FL_OFF_CTX_TO_A);
                if (a) {
                    void* mgr = *(void**)((char*)a + FL_OFF_A_TO_MGR);
                    if (mgr) {
                        void*** vtbl = (void***)mgr;
                        FL_GetAllFn getAll = (FL_GetAllFn)(*vtbl)[FL_VTBL_SLOT_GETALL];
                        unsigned char vecBuf[32];
                        memset(vecBuf, 0, sizeof(vecBuf));
                        fl_pVecCtor(vecBuf);
                        getAll(mgr, vecBuf, 0);
                        unsigned __int64 count = fl_pVecSize(vecBuf);
                        BOOL first = TRUE;
                        for (unsigned __int64 i = 0; i < count; i++) {
                            void** slot = (void**)fl_pVecAt(vecBuf, i);
                            const char* name = (slot && *slot) ? fl_pModelName(*slot) : NULL;
                            if (!name) continue;
                            if (!first) FL_SbAppend(&sb, ",");
                            first = FALSE;
                            FL_SbAppendJsonStringDeduped(&sb, name);
                        }
                        fl_pVecDtor(vecBuf);
                    }
                }
            }
            FL_SbAppend(&sb, "]");
            FL_WriteWholeFileW(jsonPath, sb.data, sb.len);
            FL_SbFree(&sb);
        } else if (!jsonPath) {
            FL_DebugLog("!! no save path available, skipped writing json");
        } else {
            FL_DebugLog("!! model-list exports not resolved, skipped writing json");
        }
        if (jsonPath) free(jsonPath);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FL_DebugLog("!! exception 0x%08X in hook", (unsigned int)GetExceptionCode());
    }
    return fl_pOrigTrampoline(param1, param2, param3);
}

static BOOL FL_InstallHook(void) {
    HMODULE exeMod = GetModuleHandleA(NULL);
    HMODULE algoMod = GetModuleHandleA("librabbit_algorithm.dll");
    if (!algoMod) algoMod = LoadLibraryA("librabbit_algorithm.dll");
    if (!exeMod || !algoMod) { FL_DebugLog("!! could not resolve exe base or librabbit_algorithm.dll"); return FALSE; }

    fl_pVecCtor   = (FL_VecCtorFn)  GetProcAddress(algoMod, "??0?$AlgoVector@PEAVModelAbstract@algo@@@algo@@QEAA@XZ");
    fl_pVecDtor   = (FL_VecDtorFn)  GetProcAddress(algoMod, "??1?$AlgoVector@PEAVModelAbstract@algo@@@algo@@QEAA@XZ");
    fl_pVecSize   = (FL_VecSizeFn)  GetProcAddress(algoMod, "?size@?$AlgoVector@PEAVModelAbstract@algo@@@algo@@QEBA_KXZ");
    fl_pVecAt     = (FL_VecAtFn)    GetProcAddress(algoMod, "??A?$AlgoVector@PEAVModelAbstract@algo@@@algo@@QEAAAEAPEAVModelAbstract@1@_K@Z");
    fl_pModelName = (FL_ModelNameFn)GetProcAddress(algoMod, "?Name@ModelAbstract@algo@@QEBAPEBDXZ");
    if (!fl_pVecCtor || !fl_pVecDtor || !fl_pVecSize || !fl_pVecAt || !fl_pModelName) {
        FL_DebugLog("!! failed to resolve one or more librabbit_algorithm.dll exports "
                    "(ctor=%p dtor=%p size=%p at=%p name=%p)",
                    (void*)fl_pVecCtor, (void*)fl_pVecDtor, (void*)fl_pVecSize, (void*)fl_pVecAt, (void*)fl_pModelName);
    }

    fl_hookAddr = (char*)exeMod + FL_RVA_SAVESLICE;

    /* 2026-09-24: this build of CHITUBOX Pro.exe is Themida-wrapped (added
     * between the 2026-09-04 and 2026-09-14 releases - see this file's own
     * "filelist hook" section comment). RVA_SAVESLICE itself is confirmed
     * byte-identical to the old, unprotected build (live memory dump,
     * 19/19 bytes match exactly - Themida wraps the existing compiled
     * binary rather than forcing a recompile, so the underlying .text
     * layout didn't move) - but Themida decrypts/unpacks that code into
     * memory at its OWN pace during process startup, and this thread (spun
     * up from DllMain, i.e. about as early as any static-import DLL can
     * run) could easily win the race and reach this point BEFORE that
     * unpacking has happened. Patching over still-encrypted bytes would be
     * worse than a no-op - it'd corrupt Themida's own unpacking process
     * and forge/leave whatever WAS there. Poll for the known-good 19-byte
     * prologue (the exact bytes captured live via x64dbg from the real,
     * already-unpacked process, 2026-09-24) instead of patching blindly;
     * give up after a generous timeout rather than hang the app forever if
     * this build ever genuinely changes and the signature stops matching. */
    {
        static const unsigned char kExpectedPrologue[FL_PROLOGUE_LEN] = {
            0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
            0x48, 0x8D, 0xAC, 0x24, 0x80, 0xEF, 0xFF, 0xFF
        };
        const int kMaxWaitMs = 30000, kPollMs = 100;
        int waited = 0;
        BOOL ready = FALSE;
        while (waited < kMaxWaitMs) {
            __try {
                if (memcmp(fl_hookAddr, kExpectedPrologue, FL_PROLOGUE_LEN) == 0) {
                    ready = TRUE;
                    break;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                /* page not committed/readable yet - keep waiting */
            }
            Sleep(kPollMs);
            waited += kPollMs;
        }
        if (!ready) {
            FL_DebugLog("!! expected saveSliceFile prologue never appeared at %p after %dms - "
                        "Themida unpacking took too long, or this build's code really did move. Skipping install.",
                        fl_hookAddr, kMaxWaitMs);
            return FALSE;
        }
        FL_DebugLog("saveSliceFile prologue verified at %p after %dms wait", fl_hookAddr, waited);
    }

    fl_trampoline = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!fl_trampoline) { FL_DebugLog("!! VirtualAlloc for trampoline failed, gle=%lu", GetLastError()); return FALSE; }
    memcpy(fl_trampoline, fl_hookAddr, FL_PROLOGUE_LEN);
    unsigned char* t = (unsigned char*)fl_trampoline + FL_PROLOGUE_LEN;
    unsigned __int64 backAddr = (unsigned __int64)fl_hookAddr + FL_PROLOGUE_LEN;
    t[0] = 0x48; t[1] = 0xB8;
    memcpy(t + 2, &backAddr, 8);
    t[10] = 0xFF; t[11] = 0xE0;
    fl_pOrigTrampoline = (FL_SaveSliceFn)fl_trampoline;

    DWORD oldProt;
    if (!VirtualProtect(fl_hookAddr, FL_PROLOGUE_LEN, PAGE_EXECUTE_READWRITE, &oldProt)) {
        FL_DebugLog("!! VirtualProtect failed, gle=%lu", GetLastError());
        return FALSE;
    }
    unsigned char patch[FL_PROLOGUE_LEN];
    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0x48; patch[1] = 0xB8;
    unsigned __int64 hookFnAddr = (unsigned __int64)FL_HookedSaveSlice;
    memcpy(patch + 2, &hookFnAddr, 8);
    patch[10] = 0xFF; patch[11] = 0xE0;
    memcpy(fl_hookAddr, patch, sizeof(patch));
    VirtualProtect(fl_hookAddr, FL_PROLOGUE_LEN, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), fl_hookAddr, FL_PROLOGUE_LEN);

    hooklog("filelist hook (merged from ChituHook) installed at %p", fl_hookAddr);
    return TRUE;
}
/* ===================================================================== */

static DWORD WINAPI InstallHooksThread(LPVOID unused) {
    hooklog("=== goo_hook worker thread started, pid %lu ===", GetCurrentProcessId());

    /* ChituHook filelist-hook merge (2026-09-08) - was disabled the same
     * day out of caution (see git history for the original long comment),
     * then re-verified and RE-ENABLED 2026-09-24 after confirming live
     * (via x64dbg against the real, now Themida-wrapped 2026-09-14 build)
     * that RVA_SAVESLICE is still byte-identical to the original build, and
     * adding the prologue-signature wait in FL_InstallHook() above so this
     * can never patch over still-encrypted/not-yet-unpacked bytes. */
    InitializeCriticalSection(&fl_lock);
    if (FL_InstallHook()) {
        hooklog("filelist hook (merged from ChituHook) install: OK");
    } else {
        hooklog("filelist hook (merged from ChituHook) install: FAILED (see C:\\ChituHook\\chitu_hook_debug.log)");
    }

    register_cfg_valid_target((void*)Hook_CreateFileW);
    register_cfg_valid_target((void*)Hook_CloseHandle);

    void *origCreate = NULL, *origClose = NULL;
    patch_iat_everywhere("CreateFileW", (void*)Hook_CreateFileW, &origCreate);
    patch_iat_everywhere("CloseHandle", (void*)Hook_CloseHandle, &origClose);

    if (!origCreate) origCreate = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW");
    if (!origClose) origClose = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    Real_CreateFileW = (CreateFileW_t)origCreate;
    Real_CloseHandle = (CloseHandle_t)origClose;

    hooklog("hook installed: CreateFileW=%p CloseHandle=%p", origCreate, origClose);

    /* Per-layer VUF cache hooks (2026-09-07) - DISABLED (2026-09-07, same
     * day). Confirmed via two independent live captures that the buffer
     * Hook_GetSliceImageCompression reads is NOT real per-layer pixel
     * data (byte-identical across hundreds of different layers/heap
     * allocations, never contains the real 0x55 magic byte present in the
     * file's own per-layer chunks). Worse, the added diagnostic code
     * (SEH-guarded pointer scanning across ~667 calls) twice caused
     * CHITUBOX Pro to hang for real, requiring a force-kill - see
     * REVERSE_ENGINEERING_HANDOFF.md's "2026-09-07 update" section for
     * the full writeup, the real render/encode pipeline traced afterward
     * (algo::SliceImpl::GenerateImage -> sserial::ProcessorSliceImage),
     * and why this specific approach is not worth resuming. The hook
     * functions/cache-state plumbing below are left in place (dead code -
     * never installed, never called) only so a future session doesn't
     * have to reconstruct them from scratch if the real call site is ever
     * found; do NOT re-enable this without re-reading that section first.
     *
     * register_cfg_valid_target((void*)Hook_IsNeedSlicePath);
     * register_cfg_valid_target((void*)Hook_GetSliceImageCompression);
     * InitializeCriticalSection(&g_layerCacheCS);
     *
     * void *origIsNeed = NULL, *origGetSlice = NULL;
     * patch_exe_iat_for_import("librabbit_slice_serial.dll",
     *     "?IsNeedSlicePath@SliceSerailBase@sserial@@QEBA_NXZ",
     *     (void*)Hook_IsNeedSlicePath, &origIsNeed);
     * patch_exe_iat_for_import("librabbit_algorithm.dll",
     *     "?GetSliceImageCompression@SliceResult@algo@@QEAAXAEAVXImage@framework@@@Z",
     *     (void*)Hook_GetSliceImageCompression, &origGetSlice);
     * Real_IsNeedSlicePath = (IsNeedSlicePath_t)origIsNeed;
     * Real_GetSliceImageCompression = (GetSliceImageCompression_t)origGetSlice;
     * hooklog("layer-cache hooks: IsNeedSlicePath=%p GetSliceImageCompression=%p",
     *         origIsNeed, origGetSlice);
     */

    /* Network-send-button fix (2026-09-08) - RE-ENABLED, now thread-safe.
     * The 2026-09-08 crash (real, during a real Jupiter-2 Save Slice
     * export) was caused by an earlier version of this loop calling
     * probe_qml_tree()/fix_network_send_button() DIRECTLY from this
     * background thread - both touched live QWidget/QQuickItem objects,
     * which is only safe from the Qt GUI/main thread. Fixed at the root:
     * schedule_fix_network_send_button() (qml_probe.cpp) no longer
     * touches any Qt object itself - it only ever posts a
     * QMetaObject::invokeMethod(..., Qt::QueuedConnection) call (thread-
     * safe from any thread, by Qt's own documentation), which runs the
     * actual fix later, on the GUI thread's own event loop. This thread
     * just has to call that safe posting function periodically - forever,
     * not bounded to 5 minutes like the old diagnostic loop, since the
     * user may navigate to the Save Slice screen at any point in a long
     * CHITUBOX Pro session. */
    while (1) {
        Sleep(10000);
        schedule_fix_network_send_button();
    }
    return 0;
}

/* IMPORTANT: DllMain runs under the loader lock. CreateToolhelp32Snapshot
 * (and Module32First/Next, which can internally touch the loader's own
 * module list) is documented by Microsoft as unsafe to call from DllMain -
 * doing so caused this DLL to fail with ERROR_DLL_INIT_FAILED (1114) when
 * tested directly. Do all real work from a separate thread instead, spun
 * up after DllMain has already returned. */
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_cs);
        CreateThread(NULL, 0, InstallHooksThread, NULL, 0, NULL);

        /* Watch every fixed/removable drive, not just C:\ - exports can land
         * anywhere the user picks (confirmed: a real export to E:\downloads
         * was missed entirely when only C:\Users\<user> was watched, since
         * ReadDirectoryChangesW only sees changes under the directory handle
         * it was opened on). */
        DWORD driveMask = GetLogicalDrives();
        for (int i = 0; i < 26; i++) {
            if (!(driveMask & (1u << i))) continue;
            wchar_t root[8];
            root[0] = (wchar_t)('A' + i);
            root[1] = L':'; root[2] = L'\\'; root[3] = 0;
            UINT type = GetDriveTypeW(root);
            if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
            wchar_t *arg = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
            wcscpy(arg, root);
            CreateThread(NULL, 0, DirWatcherThread, arg, 0, NULL);
        }
    }
    return TRUE;
}

/* Exported purely so CHITUBOX Pro.exe's import table can reference this
 * DLL by name (added 2026-09-04 via a PE import-table patch - see
 * install_static_import.py) instead of relying on runtime
 * CreateRemoteThread+LoadLibraryW injection, which turned out to be
 * intermittently and unpredictably flaky in this environment (confirmed
 * failing for byte-identical DLL builds across different launches of the
 * same target process, for reasons never pinned down - see
 * GOO_V3_V5_FORMAT_NOTES.md "2026-09-04 update #7"). A static import is
 * loaded by the OS's own PE loader as an ordinary part of process
 * startup, before CHITUBOX Pro's own main() runs - the same mechanism
 * every normal DLL dependency (Qt, etc.) already relies on, so it
 * doesn't share any of CreateRemoteThread's failure modes. This function
 * is never actually called by anything - resolving it by name at load
 * time is all that's needed to make the loader map the whole DLL (and
 * run DllMain, which does all the real work). */
__declspec(dllexport) void GooHookNoop(void) {}
