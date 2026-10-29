#ifndef EMERAG_TLS_H
#define EMERAG_TLS_H

#include "common.h"

typedef struct Tls Tls;

Tls *tls_connect(const char *host, const char *connect_ip, int port, char *err, size_t errlen);
int tls_write(Tls *t, const void *data, size_t len);
int tls_read(Tls *t, void *data, size_t len);
void tls_close(Tls *t);

#endif
