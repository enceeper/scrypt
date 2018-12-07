CC=gcc
CFLAGS=

DEPS = codec/hex.h codec/base64.h lib/util.h lib/scrypt_lib.h lib/hmac_sha2.h lib/sha2.h lib/pbkdf2.h
OBJ = codec/hex.o codec/base64.o lib/util.o lib/scrypt_lib.o lib/hmac_sha2.o lib/sha2.o lib/pbkdf2.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

scrypt: $(OBJ) scrypt.c
	$(CC) -o $@ $^ $(CFLAGS)

scrypt_romix: $(OBJ) scrypt_romix.c
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f codec/*.o lib/*.o scrypt_romix scrypt
