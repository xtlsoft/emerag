#include "crypto.h"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int unhex(const char *s, u8 *out, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        int a = hexval(s[i*2]);
        int b = hexval(s[i*2+1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (u8)((a << 4) | b);
    }
    return 0;
}

static void show(const char *name, const u8 *p, size_t n) {
    size_t i;
    printf("%s ", name);
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static int check(const char *name, const u8 *got, const char *hex, size_t n) {
    u8 want[64];
    if (unhex(hex, want, n) != 0 || memcmp(got, want, n) != 0) {
        show(name, got, n);
        printf("FAIL %s\n", name);
        return 1;
    }
    printf("ok %s\n", name);
    return 0;
}

int main(void) {
    int fail = 0;
    u8 out[64];
    u8 key[32], data[32], aad[32], tag[16], in[32], ct[32], pt[32];
    u8 scalar[32], point[32];

    sha256("abc", 3, out);
    fail |= check("sha256", out,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);

    memset(key, 0x0b, 20);
    hmac_sha256(key, 20, "Hi There", 8, out);
    fail |= check("hmac", out,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32);

    {
        Aes128 a;
        int i;
        for (i = 0; i < 16; i++) key[i] = (u8)i;
        for (i = 0; i < 16; i++) in[i] = (u8)(i * 0x11);
        aes128_init(&a, key);
        aes128_encrypt_block(&a, in, out);
        fail |= check("aes128", out, "69c4e0d86a7b0430d8cdb78070b4c55a", 16);
    }

    {
        memset(key, 0, 16);
        memset(data, 0, 16);
        memset(tag, 0, 16);
        memset(aad, 0, 12);
        gcm_encrypt(key, aad, aad, 0, data, 16, ct, tag);
        fail |= check("gcm-tag", tag, "ab6e47d42cec13bdf53a67b21257bddf", 16);
        if (gcm_decrypt(key, aad, aad, 0, ct, 16, pt, tag) != 0 ||
            memcmp(pt, data, 16) != 0) {
            printf("FAIL gcm-decrypt\n"); fail = 1;
        } else printf("ok gcm-decrypt\n");
    }

    if (unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar, 32) ||
        unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point, 32)) {
        printf("FAIL x25519 setup\n"); return 1;
    }
    x25519(out, scalar, point);
    fail |= check("x25519", out,
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 32);

    if (unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", scalar, 32)) return 1;
    x25519_base(out, scalar);
    fail |= check("x25519-base", out,
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32);

    return fail;
}
