#include "crypto.h"
#include <time.h>

/* ---------------- SHA-256 ---------------- */

static const u32 sha_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static u32 rotr32(u32 x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(Sha256 *c, const u8 *p) {
    u32 w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((u32)p[i*4] << 24) | ((u32)p[i*4+1] << 16) |
               ((u32)p[i*4+2] << 8) | (u32)p[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        u32 s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        u32 s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (i = 0; i < 64; i++) {
        u32 s1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        u32 ch = (e & f) ^ ((~e) & g);
        u32 s0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        u32 maj = (a & b) ^ (a & cc) ^ (b & cc);
        t1 = h + s1 + ch + sha_k[i] + w[i];
        t2 = s0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

void sha256_init(Sha256 *c) {
    c->h[0]=0x6a09e667u; c->h[1]=0xbb67ae85u;
    c->h[2]=0x3c6ef372u; c->h[3]=0xa54ff53au;
    c->h[4]=0x510e527fu; c->h[5]=0x9b05688cu;
    c->h[6]=0x1f83d9abu; c->h[7]=0x5be0cd19u;
    c->len=0; c->n=0;
}

void sha256_update(Sha256 *c, const void *data, size_t n) {
    const u8 *p = (const u8 *)data;
    c->len += (u64)n;
    while (n > 0) {
        size_t take = 64 - c->n;
        if (take > n) take = n;
        memcpy(c->buf + c->n, p, take);
        c->n += take;
        p += take;
        n -= take;
        if (c->n == 64) {
            sha256_transform(c, c->buf);
            c->n = 0;
        }
    }
}

void sha256_final(Sha256 *c, u8 out[32]) {
    u64 bits = c->len * 8;
    size_t i = c->n;
    c->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) c->buf[i++] = 0;
        sha256_transform(c, c->buf);
        i = 0;
    }
    while (i < 56) c->buf[i++] = 0;
    for (i = 0; i < 8; i++) {
        c->buf[63-i] = (u8)(bits >> (i*8));
    }
    sha256_transform(c, c->buf);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (u8)(c->h[i] >> 24);
        out[i*4+1] = (u8)(c->h[i] >> 16);
        out[i*4+2] = (u8)(c->h[i] >> 8);
        out[i*4+3] = (u8)c->h[i];
    }
}

void sha256(const void *data, size_t n, u8 out[32]) {
    Sha256 c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

/* ---------------- HMAC / HKDF ---------------- */

void hmac_sha256(const u8 *key, size_t keylen,
                 const void *data, size_t datalen, u8 out[32]) {
    u8 k[64], ipad[64], opad[64], inner[32];
    Sha256 c;
    size_t i;
    memset(k, 0, sizeof(k));
    if (keylen > 64) sha256(key, keylen, k);
    else memcpy(k, key, keylen);
    for (i = 0; i < 64; i++) {
        ipad[i] = (u8)(k[i] ^ 0x36);
        opad[i] = (u8)(k[i] ^ 0x5c);
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, data, datalen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

void hkdf_extract(const u8 *salt, size_t saltlen,
                  const u8 *ikm, size_t ikmlen, u8 out[32]) {
    u8 zero[32];
    if (!salt || saltlen == 0) {
        memset(zero, 0, sizeof(zero));
        salt = zero;
        saltlen = sizeof(zero);
    }
    hmac_sha256(salt, saltlen, ikm, ikmlen, out);
}

void hkdf_expand(const u8 prk[32], const u8 *info, size_t infolen,
                 u8 *out, size_t outlen) {
    u8 t[32], block[32];
    size_t done = 0, tlen = 0;
    u8 counter = 1;
    memset(t, 0, sizeof(t));
    while (done < outlen) {
        size_t n;
        u8 *tmp = (u8 *)nano_alloc(tlen + infolen + 1);
        if (tlen) memcpy(tmp, t, tlen);
        if (infolen) memcpy(tmp + tlen, info, infolen);
        tmp[tlen + infolen] = counter;
        hmac_sha256(prk, 32, tmp, tlen + infolen + 1, block);
        nano_free(tmp);
        tlen = 32;
        memcpy(t, block, 32);
        n = outlen - done;
        if (n > 32) n = 32;
        memcpy(out + done, block, n);
        done += n;
        counter++;
    }
}

void hkdf_expand_label(const u8 secret[32], const char *label,
                       const u8 *context, size_t ctxlen,
                       u8 *out, size_t outlen) {
    u8 info[300];
    size_t label_len = strlen(label);
    size_t pos = 0;
    info[pos++] = (u8)(outlen >> 8);
    info[pos++] = (u8)outlen;
    info[pos++] = (u8)(6 + label_len);
    memcpy(info + pos, "tls13 ", 6); pos += 6;
    memcpy(info + pos, label, label_len); pos += label_len;
    info[pos++] = (u8)ctxlen;
    if (ctxlen) { memcpy(info + pos, context, ctxlen); pos += ctxlen; }
    hkdf_expand(secret, info, pos, out, outlen);
}

/* ---------------- AES-128 ---------------- */

static const u8 aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static u8 xtime(u8 x) {
    return (u8)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

void aes128_init(Aes128 *a, const u8 key[16]) {
    u8 rcon = 1;
    int i, j;
    memcpy(a->rk, key, 16);
    for (i = 4; i < 44; i++) {
        u8 t[4];
        memcpy(t, a->rk + (i-1)*4, 4);
        if (i % 4 == 0) {
            u8 x = t[0];
            t[0] = aes_sbox[t[1]] ^ rcon;
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[x];
            rcon = xtime(rcon);
        }
        for (j = 0; j < 4; j++) {
            a->rk[i*4+j] = (u8)(a->rk[(i-4)*4+j] ^ t[j]);
        }
    }
}

static void aes_add_round_key(u8 *s, const u8 *rk) {
    int i;
    for (i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void aes_sub_shift(u8 *s) {
    u8 t[16];
    int i, r, c;
    for (i = 0; i < 16; i++) t[i] = aes_sbox[s[i]];
    /* state is column-major: s[c*4+r]; shift row r left by r */
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            s[c*4+r] = t[((c + r) & 3)*4 + r];
        }
    }
}

static void aes_mix_columns(u8 *s) {
    int c;
    for (c = 0; c < 4; c++) {
        u8 *p = s + c*4;
        u8 a0=p[0], a1=p[1], a2=p[2], a3=p[3];
        u8 all = (u8)(a0 ^ a1 ^ a2 ^ a3);
        p[0] ^= (u8)(all ^ xtime((u8)(a0 ^ a1)));
        p[1] ^= (u8)(all ^ xtime((u8)(a1 ^ a2)));
        p[2] ^= (u8)(all ^ xtime((u8)(a2 ^ a3)));
        p[3] ^= (u8)(all ^ xtime((u8)(a3 ^ a0)));
    }
}

void aes128_encrypt_block(const Aes128 *a, const u8 in[16], u8 out[16]) {
    u8 s[16];
    int round;
    memcpy(s, in, 16);
    aes_add_round_key(s, a->rk);
    for (round = 1; round < 10; round++) {
        aes_sub_shift(s);
        aes_mix_columns(s);
        aes_add_round_key(s, a->rk + round*16);
    }
    aes_sub_shift(s);
    aes_add_round_key(s, a->rk + 160);
    memcpy(out, s, 16);
}

/* ---------------- GHASH / AES-GCM ---------------- */

static u32 load_be32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
           ((u32)p[2] << 8) | (u32)p[3];
}

static void ghash_gf_mul(u32 z[4], const u32 x[4], const u32 h[4]) {
    u32 v[4], y[4], xx[4];
    int i, j;
    for (i = 0; i < 4; i++) { v[i] = h[i]; xx[i] = x[i]; y[i] = 0; }
    for (i = 0; i < 128; i++) {
        if ((xx[i >> 5] >> (31 - (i & 31))) & 1) {
            for (j = 0; j < 4; j++) y[j] ^= v[j];
        }
        if (v[3] & 1) {
            for (j = 3; j > 0; j--) v[j] = (v[j] >> 1) | (v[j-1] << 31);
            v[0] = (v[0] >> 1) ^ 0xe1000000u;
        } else {
            for (j = 3; j > 0; j--) v[j] = (v[j] >> 1) | (v[j-1] << 31);
            v[0] >>= 1;
        }
    }
    for (i = 0; i < 4; i++) z[i] = y[i];
}

static void ghash_block(u32 y[4], const u32 h[4], const u8 block[16]) {
    u32 x[4], z[4];
    int i;
    for (i = 0; i < 4; i++) x[i] = load_be32(block + i*4);
    for (i = 0; i < 4; i++) x[i] ^= y[i];
    ghash_gf_mul(z, x, h);
    for (i = 0; i < 4; i++) y[i] = z[i];
}

static void ghash_data(u32 y[4], const u32 h[4], const u8 *p, size_t n) {
    while (n >= 16) {
        ghash_block(y, h, p);
        p += 16;
        n -= 16;
    }
    if (n) {
        u8 tmp[16];
        memset(tmp, 0, 16);
        memcpy(tmp, p, n);
        ghash_block(y, h, tmp);
    }
}

static void ghash_len(u32 y[4], const u32 h[4], u64 aad_bits, u64 data_bits) {
    u8 tmp[16];
    int i;
    for (i = 0; i < 8; i++) {
        tmp[7-i] = (u8)(aad_bits >> (i*8));
        tmp[15-i] = (u8)(data_bits >> (i*8));
    }
    ghash_block(y, h, tmp);
}

static void gcm_core(const u8 key[16], const u8 iv[12],
                     const u8 *aad, size_t aadlen,
                     const u8 *in, size_t len,
                     u8 *out, u8 tag[16], int encrypt) {
    Aes128 a;
    u32 h[4], y[4];
    u8 zero[16], block[16], j0[16], ctr[16], stream[16], mask[16];
    u8 *ct = (u8 *)nano_alloc(len ? len : 1);
    size_t off;
    int i;

    memset(zero, 0, 16);
    aes128_init(&a, key);
    aes128_encrypt_block(&a, zero, block);
    for (i = 0; i < 4; i++) h[i] = load_be32(block + i*4);

    memset(y, 0, sizeof(y));
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    ghash_data(y, h, aad, aadlen);
    if (encrypt) {
        /* encrypt first, then GHASH ciphertext */
        memcpy(ctr, j0, 16);
        for (off = 0; off < len; off += 16) {
            size_t n = len - off;
            if (n > 16) n = 16;
            /* inc32 */
            {
                u32 v = ((u32)ctr[12] << 24) | ((u32)ctr[13] << 16) |
                        ((u32)ctr[14] << 8) | (u32)ctr[15];
                v++;
                ctr[12] = (u8)(v >> 24); ctr[13] = (u8)(v >> 16);
                ctr[14] = (u8)(v >> 8); ctr[15] = (u8)v;
            }
            aes128_encrypt_block(&a, ctr, stream);
            for (i = 0; i < (int)n; i++) {
                ct[off+i] = (u8)(in[off+i] ^ stream[i]);
                out[off+i] = ct[off+i];
            }
        }
        ghash_data(y, h, ct, len);
    } else {
        memcpy(ct, in, len);
        ghash_data(y, h, ct, len);
    }
    ghash_len(y, h, (u64)aadlen * 8, (u64)len * 8);
    aes128_encrypt_block(&a, j0, mask);
    for (i = 0; i < 16; i++) tag[i] = (u8)(mask[i] ^ ((y[i/4] >> (24 - (i%4)*8)) & 0xff));

    if (!encrypt) {
        memcpy(ctr, j0, 16);
        for (off = 0; off < len; off += 16) {
            size_t n = len - off;
            if (n > 16) n = 16;
            {
                u32 v = ((u32)ctr[12] << 24) | ((u32)ctr[13] << 16) |
                        ((u32)ctr[14] << 8) | (u32)ctr[15];
                v++;
                ctr[12] = (u8)(v >> 24); ctr[13] = (u8)(v >> 16);
                ctr[14] = (u8)(v >> 8); ctr[15] = (u8)v;
            }
            aes128_encrypt_block(&a, ctr, stream);
            for (i = 0; i < (int)n; i++) {
                out[off+i] = (u8)(in[off+i] ^ stream[i]);
            }
        }
    }
    nano_free(ct);
}

void gcm_encrypt(const u8 key[16], const u8 iv[12],
                 const u8 *aad, size_t aadlen,
                 const u8 *in, size_t len,
                 u8 *out, u8 tag[16]) {
    gcm_core(key, iv, aad, aadlen, in, len, out, tag, 1);
}

int gcm_decrypt(const u8 key[16], const u8 iv[12],
                const u8 *aad, size_t aadlen,
                const u8 *in, size_t len,
                u8 *out, const u8 tag[16]) {
    u8 real[16];
    int i, diff = 0;
    gcm_core(key, iv, aad, aadlen, in, len, out, real, 0);
    for (i = 0; i < 16; i++) diff |= real[i] ^ tag[i];
    return diff == 0 ? 0 : -1;
}

/* ---------------- X25519 (TweetNaCl-style field) ---------------- */

typedef i64 gf[16];

static const gf gf_121665 = {0xDB41, 1};

static void gf_car(gf o) {
    int i;
    i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += ((i64)1 << 16);
        c = o[i] >> 16;
        o[(i+1)*(i<15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void gf_sel(gf p, gf q, int b) {
    i64 t, i, c = ~(b - 1);
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void gf_pack(u8 *o, const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    gf_car(t); gf_car(t); gf_car(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        gf_sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2*i] = (u8)(t[i] & 0xff);
        o[2*i+1] = (u8)(t[i] >> 8);
    }
}

static void gf_unpack(gf o, const u8 *n) {
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2*i] + ((i64)n[2*i+1] << 8);
    o[15] &= 0x7fff;
}

static void gf_add(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
    gf_car(o);
}

static void gf_sub(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
    gf_car(o);
}

static void gf_mul(gf o, const gf a, const gf b) {
    i64 t[31];
    int i, j;
    memset(t, 0, sizeof(t));
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i+j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i+16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    gf_car(o); gf_car(o);
}

static void gf_sq(gf o, const gf a) {
    gf_mul(o, a, a);
}

static void gf_inv(gf o, const gf i) {
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        gf_sq(c, c);
        if (a != 2 && a != 4) gf_mul(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

int x25519(u8 out[32], const u8 scalar[32], const u8 point[32]) {
    u8 z[32];
    i64 x[80];
    gf a, b, c, d, e, f;
    int i;
    for (i = 0; i < 31; i++) z[i] = scalar[i];
    z[31] = (u8)((scalar[31] & 127) | 64);
    z[0] &= 248;
    gf_unpack(x, point);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        a[i] = c[i] = d[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        gf_sel(a, b, r);
        gf_sel(c, d, r);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sq(d, e);
        gf_sq(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sq(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, gf_121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sq(b, e);
        gf_sel(a, b, r);
        gf_sel(c, d, r);
    }
    for (i = 0; i < 16; i++) {
        x[i+16] = a[i];
        x[i+32] = c[i];
        x[i+48] = b[i];
        x[i+64] = d[i];
    }
    gf_inv(x+32, x+32);
    gf_mul(x+16, x+16, x+32);
    gf_pack(out, x+16);
    return 0;
}

int x25519_base(u8 out[32], const u8 scalar[32]) {
    static const u8 base[32] = {9};
    return x25519(out, scalar, base);
}

/* ---------------- OS randomness ---------------- */

int nano_random(u8 *buf, size_t n) {
#ifdef _WIN32
    HCRYPTPROV prov;
    if (CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(prov, (DWORD)n, buf)) {
            CryptReleaseContext(prov, 0);
            return 0;
        }
        CryptReleaseContext(prov, 0);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t got = fread(buf, 1, n, f);
        fclose(f);
        if (got == n) return 0;
    }
#endif
    {
        static int warned = 0;
        u64 s = (u64)time(NULL) ^ ((u64)clock() << 16);
#ifdef _WIN32
        s ^= (u64)GetTickCount() << 32;
        s ^= (u64)GetCurrentProcessId();
#endif
        size_t i;
        if (!warned) {
            warned = 1;
            fprintf(stderr, "emerag-nano: warning: weak randomness fallback\n");
        }
        for (i = 0; i < n; i++) {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s *= ((u64)0x2545F491u << 32) | (u64)0x4F6CDD1Du;
            buf[i] = (u8)(s >> 32);
        }
    }
    return 0;
}
