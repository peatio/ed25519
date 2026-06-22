CC ?= gcc
CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
CFLAGS += -I $(CURDIR)/../c_src/
LDFLAGS += -L $(CURDIR)/../priv/

test: test.c $(CURDIR)/../priv/ed25519.so $(CURDIR)/../c_src/sha512.o
	$(CC) $(CFLAGS) -o test test.c $(CURDIR)/../c_src/sha512.o $(CURDIR)/../priv/ed25519.so $(LDFLAGS)

clean:
	@rm -f test
