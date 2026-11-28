CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcrypto

all: test_crypto

vault_crypto.o: vault_crypto.c vault_crypto.h
	$(CC) $(CFLAGS) -c vault_crypto.c -o vault_crypto.o

test_crypto: test_crypto.c vault_crypto.o
	$(CC) $(CFLAGS) test_crypto.c vault_crypto.o -o test_crypto $(LIBS)

test: test_crypto
	./test_crypto

clean:
	rm -f *.o test_crypto