CC ?= gcc
CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
CFLAGS += -I $(CURDIR)/../c_src/
LDFLAGS += -L $(CURDIR)/../priv/

test: test.c $(CURDIR)/../priv/ed25519.so $(CURDIR)/../c_src/sha512.o $(CURDIR)/../c_src/mixin.o $(CURDIR)/../c_src/ge.o  $(CURDIR)/../c_src/sc.o 
	$(CC) $(CFLAGS) -o test test.c $(CURDIR)/../c_src/sha512.o $(CURDIR)/../c_src/mixin.o $(CURDIR)/../c_src/ge.o  $(CURDIR)/../c_src/sc.o $(CURDIR)/../priv/ed25519.so $(LDFLAGS)

clean:
	@rm -f test
