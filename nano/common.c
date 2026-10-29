#include "common.h"

void *nano_alloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "emerag-nano: out of memory\n");
        exit(1);
    }
    return p;
}

void nano_free(void *p) {
    if (p) free(p);
}

void buf_init(Buf *b) {
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_free(Buf *b) {
    if (b->p) free(b->p);
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

int buf_reserve(Buf *b, size_t extra) {
    size_t need = b->len + extra;
    size_t cap;
    u8 *p;
    if (need <= b->cap) return 0;
    cap = b->cap ? b->cap : 256;
    while (cap < need) cap *= 2;
    p = (u8 *)realloc(b->p, cap);
    if (!p) return -1;
    b->p = p;
    b->cap = cap;
    return 0;
}

int buf_put(Buf *b, const void *data, size_t n) {
    if (n == 0) return 0;
    if (buf_reserve(b, n) != 0) return -1;
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return 0;
}

int buf_putc(Buf *b, int c) {
    u8 ch = (u8)c;
    return buf_put(b, &ch, 1);
}

int buf_puts(Buf *b, const char *s) {
    return buf_put(b, s, strlen(s));
}

void buf_clear(Buf *b) {
    b->len = 0;
}
