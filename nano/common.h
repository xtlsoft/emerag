#ifndef EMERAG_COMMON_H
#define EMERAG_COMMON_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
typedef int nano_socklen;
#define NANO_CLOSE closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
typedef socklen_t nano_socklen;
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define NANO_CLOSE close
#endif

#ifdef _MSC_VER
typedef unsigned __int64 u64;
typedef __int64 i64;
#else
typedef unsigned long long u64;
typedef long long i64;
#endif
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

typedef struct {
    u8 *p;
    size_t len;
    size_t cap;
} Buf;

void *nano_alloc(size_t n);
void nano_free(void *p);
void buf_init(Buf *b);
void buf_free(Buf *b);
int buf_reserve(Buf *b, size_t extra);
int buf_put(Buf *b, const void *data, size_t n);
int buf_putc(Buf *b, int c);
int buf_puts(Buf *b, const char *s);
void buf_clear(Buf *b);

#endif
