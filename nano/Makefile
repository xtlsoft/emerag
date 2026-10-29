CC ?= cc
CFLAGS ?= -std=gnu89 -Os -Wall -Wextra
OBJS = common.o crypto.o tls.o emerag.o

all: emerag-nano

emerag-nano: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c
crypto.o: crypto.c crypto.h common.h
	$(CC) $(CFLAGS) -c crypto.c
tls.o: tls.c tls.h common.h crypto.h
	$(CC) $(CFLAGS) -c tls.c
emerag.o: emerag.c tls.h crypto.h common.h
	$(CC) $(CFLAGS) -c emerag.c

test_crypto: test_crypto.c crypto.c common.c
	$(CC) $(CFLAGS) -o $@ test_crypto.c crypto.c common.c
	./test_crypto

clean:
	rm -f $(OBJS) emerag-nano test_crypto
