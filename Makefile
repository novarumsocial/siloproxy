CC ?= cc
CFLAGS ?= -O2 -pipe -Wall -Wextra
LDLIBS := $(shell pkg-config --cflags --libs openssl) -pthread

siloproxy: src/main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f siloproxy

.PHONY: clean
