#include "tls.h"
#include "crypto.h"

struct Tls {
    SOCKET sock;
    int encrypted;              /* 0 = plaintext, 1 = handshake, 2 = app */
    u8 ckey[16], civ[12];
    u8 skey[16], siv[12];
    u64 cseq, sseq;
    Buf hs;
    Buf app;
    Buf transcript;
};

static void set_err(char *err, size_t errlen, const char *msg) {
    if (!err || errlen == 0) return;
    strncpy(err, msg, errlen - 1);
    err[errlen - 1] = 0;
}

static int send_all(SOCKET s, const u8 *p, size_t n) {
    while (n > 0) {
        int chunk = n > 16384 ? 16384 : (int)n;
#ifdef _WIN32
        int r = send(s, (const char *)p, chunk, 0);
#else
        int r = (int)send(s, (const char *)p, chunk, 0);
#endif
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static int recv_all(SOCKET s, u8 *p, size_t n) {
    while (n > 0) {
#ifdef _WIN32
        int r = recv(s, (char *)p, (int)n, 0);
#else
        int r = (int)recv(s, (char *)p, n, 0);
#endif
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static void put_u16(Buf *b, u16 v) {
    u8 x[2];
    x[0] = (u8)(v >> 8);
    x[1] = (u8)v;
    buf_put(b, x, 2);
}

static void put_u24(Buf *b, u32 v) {
    u8 x[3];
    x[0] = (u8)(v >> 16);
    x[1] = (u8)(v >> 8);
    x[2] = (u8)v;
    buf_put(b, x, 3);
}

static u16 get_u16(const u8 *p) {
    return (u16)(((u16)p[0] << 8) | p[1]);
}

static u32 get_u24(const u8 *p) {
    return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2];
}

static void nonce_for(u8 nonce[12], const u8 iv[12], u64 seq) {
    int i;
    memcpy(nonce, iv, 12);
    for (i = 0; i < 8; i++) {
        nonce[11-i] ^= (u8)(seq >> (i*8));
    }
}

static int send_record(Tls *t, int type, const u8 *data, size_t len) {
    u8 hdr[5];
    if (!t->encrypted) {
        hdr[0] = (u8)type;
        hdr[1] = 0x03;
        hdr[2] = 0x01;
        hdr[3] = (u8)(len >> 8);
        hdr[4] = (u8)len;
        if (send_all(t->sock, hdr, 5) != 0) return -1;
        return send_all(t->sock, data, len);
    } else {
        Buf inner, out;
        u8 nonce[12], tag[16], aad[5];
        size_t total;
        buf_init(&inner);
        buf_init(&out);
        buf_put(&inner, data, len);
        buf_putc(&inner, type);
        total = inner.len + 16;
        aad[0] = 23; aad[1] = 0x03; aad[2] = 0x03;
        aad[3] = (u8)(total >> 8); aad[4] = (u8)total;
        buf_reserve(&out, inner.len);
        out.len = inner.len;
        nonce_for(nonce, t->civ, t->cseq);
        gcm_encrypt(t->ckey, nonce, aad, 5,
                    inner.p, inner.len, out.p, tag);
        hdr[0] = 23; hdr[1] = 0x03; hdr[2] = 0x03;
        hdr[3] = (u8)(total >> 8); hdr[4] = (u8)total;
        if (send_all(t->sock, hdr, 5) != 0 ||
            send_all(t->sock, out.p, out.len) != 0 ||
            send_all(t->sock, tag, 16) != 0) {
            buf_free(&inner); buf_free(&out); return -1;
        }
        t->cseq++;
        buf_free(&inner); buf_free(&out);
        return 0;
    }
}

static int read_record(Tls *t, int *type, Buf *out) {
    u8 hdr[5];
    u8 *payload;
    size_t len;
    int outer;
    for (;;) {
        if (recv_all(t->sock, hdr, 5) != 0) return -1;
        outer = hdr[0];
        len = ((size_t)hdr[3] << 8) | hdr[4];
        if (len == 0 || len > 18432) return -1;
        payload = (u8 *)nano_alloc(len);
        if (recv_all(t->sock, payload, len) != 0) { nano_free(payload); return -1; }
        if (outer == 20) { nano_free(payload); continue; } /* CCS */
        if (outer == 21) { nano_free(payload); return -1; } /* alert */
        if (!t->encrypted || outer != 23) {
            *type = outer;
            buf_put(out, payload, len);
            nano_free(payload);
            return 0;
        } else {
            u8 nonce[12], aad[5];
            Buf plain;
            size_t i, clen = len - 16;
            int inner = 0;
            if (len < 17) { nano_free(payload); return -1; }
            aad[0] = 23; aad[1] = 0x03; aad[2] = 0x03;
            aad[3] = hdr[3]; aad[4] = hdr[4];
            nonce_for(nonce, t->siv, t->sseq);
            buf_init(&plain);
            buf_reserve(&plain, clen);
            plain.len = clen;
            if (gcm_decrypt(t->skey, nonce, aad, 5, payload, clen,
                            plain.p, payload + clen) != 0) {
                buf_free(&plain); nano_free(payload); return -1;
            }
            t->sseq++;
            for (i = clen; i > 0; i--) {
                if (plain.p[i-1] != 0) { inner = plain.p[i-1]; plain.len = i - 1; break; }
            }
            nano_free(payload);
            if (inner == 23) {
                *type = 23;
                buf_put(out, plain.p, plain.len);
                buf_free(&plain);
                return 0;
            } else if (inner == 22) {
                *type = 22;
                buf_put(out, plain.p, plain.len);
                buf_free(&plain);
                return 0;
            } else if (inner == 21) {
                buf_free(&plain); return -1;
            } else {
                buf_free(&plain); return -1;
            }
        }
    }
}

static int hs_next(Tls *t, u8 **out, size_t *outlen) {
    for (;;) {
        size_t total;
        u8 *msg;
        int type;
        Buf rec;
        if (t->hs.len >= 4) {
            total = 4 + get_u24(t->hs.p + 1);
            if (total > 65536) return -1;
            if (t->hs.len >= total) {
                msg = (u8 *)nano_alloc(total);
                memcpy(msg, t->hs.p, total);
                buf_put(&t->transcript, msg, total);
                memmove(t->hs.p, t->hs.p + total, t->hs.len - total);
                t->hs.len -= total;
                *out = msg;
                *outlen = total;
                return msg[0];
            }
        }
        buf_init(&rec);
        if (read_record(t, &type, &rec) != 0) { buf_free(&rec); return -1; }
        if (type != 22) { buf_free(&rec); return -1; }
        buf_put(&t->hs, rec.p, rec.len);
        buf_free(&rec);
    }
}

static void derive_secret(const u8 secret[32], const char *label,
                          const u8 th[32], u8 out[32]) {
    hkdf_expand_label(secret, label, th, 32, out, 32);
}

static void traffic_keys(const u8 secret[32], u8 key[16], u8 iv[12]) {
    hkdf_expand_label(secret, "key", NULL, 0, key, 16);
    hkdf_expand_label(secret, "iv", NULL, 0, iv, 12);
}

static int parse_server_hello(const u8 *msg, size_t msglen,
                              u8 server_pub[32], char *err, size_t errlen) {
    size_t off = 4;
    size_t end;
    u16 cipher, extlen;
    int have_version = 0, have_key = 0, have_hrr = 0;
    static const u8 hrr_random[32] = {
        0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,
        0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
        0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,
        0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
    };
    if (msglen < 4 + 2 + 32 + 1 + 2 + 1) { set_err(err, errlen, "short ServerHello"); return -1; }
    if (memcmp(msg + 4 + 2, hrr_random, 32) == 0) have_hrr = 1;
    off = 4 + 2 + 32;
    {
        u8 sidlen = msg[off++];
        off += sidlen;
    }
    if (off + 3 > msglen) { set_err(err, errlen, "short ServerHello"); return -1; }
    cipher = get_u16(msg + off); off += 2;
    off += 1; /* compression */
    if (off + 2 > msglen) { set_err(err, errlen, "short ServerHello ext"); return -1; }
    extlen = get_u16(msg + off); off += 2;
    end = off + extlen;
    if (end > msglen) { set_err(err, errlen, "bad ServerHello ext length"); return -1; }
    while (off + 4 <= end) {
        u16 et = get_u16(msg + off);
        u16 el = get_u16(msg + off + 2);
        off += 4;
        if (off + el > end) { set_err(err, errlen, "bad extension"); return -1; }
        if (et == 43 && el == 2) {
            if (get_u16(msg + off) == 0x0304) have_version = 1;
        } else if (et == 51 && el >= 4) {
            u16 group = get_u16(msg + off);
            u16 klen = get_u16(msg + off + 2);
            if (group == 29 && klen == 32 && el >= 4 + 32) {
                memcpy(server_pub, msg + off + 4, 32);
                have_key = 1;
            }
        }
        off += el;
    }
    if (have_hrr) { set_err(err, errlen, "server requested HelloRetryRequest"); return -1; }
    if (cipher != 0x1301) { set_err(err, errlen, "server did not select TLS_AES_128_GCM_SHA256"); return -1; }
    if (!have_version) { set_err(err, errlen, "server did not negotiate TLS 1.3"); return -1; }
    if (!have_key) { set_err(err, errlen, "server did not send an X25519 key share"); return -1; }
    return 0;
}

Tls *tls_connect(const char *host, const char *connect_ip, int port, char *err, size_t errlen) {
    Tls *t;
    struct hostent *he;
    struct sockaddr_in sa;
    SOCKET s;
    u8 random[32], session[32], priv[32], pub[32], server_pub[32], shared[32];
    u8 early[32], zeros[32], derived[32], hs_secret[32], th[32];
    u8 c_hs[32], s_hs[32], c_fin[32], master[32], c_ap[32], s_ap[32];
    Buf ch, ext, body;
    int type;
    u8 *msg;
    size_t msglen;
    int done = 0;

#ifdef _WIN32
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
    }
#endif
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { set_err(err, errlen, "socket failed"); return NULL; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u16)port);
    if (connect_ip && *connect_ip) {
        sa.sin_addr.s_addr = inet_addr(connect_ip);
        if (sa.sin_addr.s_addr == INADDR_NONE) {
            set_err(err, errlen, "bad --ip address"); NANO_CLOSE(s); return NULL;
        }
    } else {
        he = gethostbyname(host);
        if (!he) { set_err(err, errlen, "DNS lookup failed"); NANO_CLOSE(s); return NULL; }
        memcpy(&sa.sin_addr, he->h_addr, (size_t)he->h_length);
    }
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        set_err(err, errlen, "TCP connect failed"); NANO_CLOSE(s); return NULL;
    }
#ifdef _WIN32
    {
        DWORD tv = 30000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    }
#else
    {
        struct timeval tv;
        tv.tv_sec = 30; tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
#endif

    t = (Tls *)nano_alloc(sizeof(Tls));
    memset(t, 0, sizeof(*t));
    t->sock = s;
    buf_init(&t->hs);
    buf_init(&t->app);
    buf_init(&t->transcript);
    nano_random(random, 32);
    nano_random(session, 32);
    nano_random(priv, 32);
    x25519_base(pub, priv);

    buf_init(&ext);
    /* SNI */
    {
        Buf sn;
        buf_init(&sn);
        put_u16(&sn, (u16)(1 + 2 + strlen(host)));
        buf_putc(&sn, 0);
        put_u16(&sn, (u16)strlen(host));
        buf_puts(&sn, host);
        put_u16(&ext, 0);
        put_u16(&ext, (u16)sn.len);
        buf_put(&ext, sn.p, sn.len);
        buf_free(&sn);
    }
    /* supported_groups: x25519 */
    put_u16(&ext, 10); put_u16(&ext, 4); put_u16(&ext, 2); put_u16(&ext, 29);
    /* signature_algorithms */
    {
        u16 algs[5];
        int i;
        algs[0] = 0x0804; algs[1] = 0x0403; algs[2] = 0x0401;
        algs[3] = 0x0805; algs[4] = 0x0503;
        put_u16(&ext, 13); put_u16(&ext, 2 + 2*5); put_u16(&ext, 2*5);
        for (i = 0; i < 5; i++) put_u16(&ext, algs[i]);
    }
    /* supported_versions: TLS 1.3 (1-byte vector length) */
    put_u16(&ext, 43); put_u16(&ext, 3); buf_putc(&ext, 2); put_u16(&ext, 0x0304);
    /* key_share: x25519 */
    put_u16(&ext, 51); put_u16(&ext, 38); put_u16(&ext, 36);
    put_u16(&ext, 29); put_u16(&ext, 32); buf_put(&ext, pub, 32);
    /* ALPN: http/1.1 */
    put_u16(&ext, 16); put_u16(&ext, 11); put_u16(&ext, 9);
    buf_putc(&ext, 8); buf_puts(&ext, "http/1.1");

    buf_init(&body);
    put_u16(&body, 0x0303);
    buf_put(&body, random, 32);
    buf_putc(&body, 32); buf_put(&body, session, 32);
    put_u16(&body, 2); put_u16(&body, 0x1301);
    buf_putc(&body, 1); buf_putc(&body, 0);
    put_u16(&body, (u16)ext.len);
    buf_put(&body, ext.p, ext.len);
    buf_free(&ext);

    buf_init(&ch);
    buf_putc(&ch, 1);
    put_u24(&ch, (u32)body.len);
    buf_put(&ch, body.p, body.len);
    buf_free(&body);

    if (send_record(t, 22, ch.p, ch.len) != 0) {
        set_err(err, errlen, "send ClientHello failed"); goto fail;
    }
    buf_put(&t->transcript, ch.p, ch.len);
    buf_free(&ch);

    type = hs_next(t, &msg, &msglen);
    if (type != 2 || msglen < 4) {
        set_err(err, errlen, "no ServerHello"); goto fail;
    }
    if (parse_server_hello(msg, msglen, server_pub, err, errlen) != 0) {
        nano_free(msg); goto fail;
    }
    nano_free(msg);

    if (x25519(shared, priv, server_pub) != 0) {
        set_err(err, errlen, "X25519 failed"); goto fail;
    }

    memset(zeros, 0, 32);
    hkdf_extract(zeros, 32, zeros, 32, early);
    sha256("", 0, th);
    derive_secret(early, "derived", th, derived);
    hkdf_extract(derived, 32, shared, 32, hs_secret);
    sha256(t->transcript.p, t->transcript.len, th);
    derive_secret(hs_secret, "c hs traffic", th, c_hs);
    derive_secret(hs_secret, "s hs traffic", th, s_hs);
    traffic_keys(c_hs, t->ckey, t->civ);
    traffic_keys(s_hs, t->skey, t->siv);
    t->encrypted = 1;
    t->cseq = 0;
    t->sseq = 0;

    while (!done) {
        type = hs_next(t, &msg, &msglen);
        if (type < 0) { set_err(err, errlen, "handshake read failed"); goto fail; }
        if (type == 20) {
            /* server Finished. Derive application secrets over transcript. */
            u8 th2[32];
            sha256(t->transcript.p, t->transcript.len, th2);
            hkdf_expand_label(c_hs, "finished", NULL, 0, c_fin, 32);
            {
                u8 verify[32];
                Buf fin;
                hmac_sha256(c_fin, 32, th2, 32, verify);
                buf_init(&fin);
                buf_putc(&fin, 20);
                put_u24(&fin, 32);
                buf_put(&fin, verify, 32);
                /* middlebox-compatible CCS, then encrypted Finished */
                {
                    u8 ccsrec[6];
                    ccsrec[0] = 20; ccsrec[1] = 0x03; ccsrec[2] = 0x03;
                    ccsrec[3] = 0; ccsrec[4] = 1; ccsrec[5] = 1;
                    if (send_all(t->sock, ccsrec, 6) != 0) {
                        buf_free(&fin); nano_free(msg);
                        set_err(err, errlen, "send CCS failed"); goto fail;
                    }
                }
                if (send_record(t, 22, fin.p, fin.len) != 0) {
                    buf_free(&fin); nano_free(msg);
                    set_err(err, errlen, "send Finished failed"); goto fail;
                }
                buf_free(&fin);
            }
            /* Only now replace the handshake keys with application keys. */
            sha256("", 0, th);
            derive_secret(hs_secret, "derived", th, derived);
            hkdf_extract(derived, 32, zeros, 32, master);
            derive_secret(master, "c ap traffic", th2, c_ap);
            derive_secret(master, "s ap traffic", th2, s_ap);
            traffic_keys(c_ap, t->ckey, t->civ);
            traffic_keys(s_ap, t->skey, t->siv);
            nano_free(msg);
            t->encrypted = 2;
            t->cseq = 0;
            t->sseq = 0;
            done = 1;
        } else {
            nano_free(msg);
        }
    }
    if (!done) { set_err(err, errlen, "handshake incomplete"); goto fail; }
    return t;

fail:
    tls_close(t);
    return NULL;
}

int tls_write(Tls *t, const void *data, size_t len) {
    const u8 *p = (const u8 *)data;
    while (len > 0) {
        size_t n = len > 16384 ? 16384 : len;
        if (send_record(t, 23, p, n) != 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

int tls_read(Tls *t, void *data, size_t len) {
    u8 *out = (u8 *)data;
    if (len == 0) return 0;
    for (;;) {
        if (t->app.len > 0) {
            size_t n = t->app.len;
            if (n > len) n = len;
            memcpy(out, t->app.p, n);
            memmove(t->app.p, t->app.p + n, t->app.len - n);
            t->app.len -= n;
            return (int)n;
        }
        {
            int type;
            Buf rec;
            buf_init(&rec);
            if (read_record(t, &type, &rec) != 0) { buf_free(&rec); return -1; }
            if (type == 23) buf_put(&t->app, rec.p, rec.len);
            buf_free(&rec);
        }
    }
}

void tls_close(Tls *t) {
    if (!t) return;
    if (t->sock != INVALID_SOCKET) NANO_CLOSE(t->sock);
    buf_free(&t->hs);
    buf_free(&t->app);
    buf_free(&t->transcript);
    nano_free(t);
}
