#ifndef EMERAG_CRYPTO_H
#define EMERAG_CRYPTO_H

#include "common.h"

typedef struct {
    u32 h[8];
    u64 len;
    u8 buf[64];
    size_t n;
} Sha256;

void sha256_init(Sha256 *c);
void sha256_update(Sha256 *c, const void *data, size_t n);
void sha256_final(Sha256 *c, u8 out[32]);
void sha256(const void *data, size_t n, u8 out[32]);

void hmac_sha256(const u8 *key, size_t keylen,
                 const void *data, size_t datalen, u8 out[32]);
void hkdf_extract(const u8 *salt, size_t saltlen,
                  const u8 *ikm, size_t ikmlen, u8 out[32]);
void hkdf_expand(const u8 prk[32], const u8 *info, size_t infolen,
                 u8 *out, size_t outlen);
void hkdf_expand_label(const u8 secret[32], const char *label,
                       const u8 *context, size_t ctxlen,
                       u8 *out, size_t outlen);

typedef struct {
    u8 rk[176];
} Aes128;

void aes128_init(Aes128 *a, const u8 key[16]);
void aes128_encrypt_block(const Aes128 *a, const u8 in[16], u8 out[16]);

void gcm_encrypt(const u8 key[16], const u8 iv[12],
                 const u8 *aad, size_t aadlen,
                 const u8 *in, size_t len,
                 u8 *out, u8 tag[16]);
int gcm_decrypt(const u8 key[16], const u8 iv[12],
                const u8 *aad, size_t aadlen,
                const u8 *in, size_t len,
                u8 *out, const u8 tag[16]);

int x25519(u8 out[32], const u8 scalar[32], const u8 point[32]);
int x25519_base(u8 out[32], const u8 scalar[32]);

int nano_random(u8 *buf, size_t n);

#endif
