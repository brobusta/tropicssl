
DESTDIR=/usr/local
PREFIX=tropicssl_

.SILENT:

all:
	make -C library all
#	make -C programs all
	make -C programs ssl/ssl_client1
	make -C programs ssl/ssl_server
	make -C programs test/selftest
	make -C test/unit all

install:
	mkdir -p $(DESTDIR)/include/tropicssl
	cp -r include/tropicssl $(DESTDIR)/include

	mkdir -p $(DESTDIR)/lib
	cp library/libtropicssl.* $(DESTDIR)/lib

	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	    fi                                  \
	done

clean:
	make -C library clean
	make -C programs clean
	make -C test/unit clean

