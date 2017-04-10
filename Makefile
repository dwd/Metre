#!/usr/bin/make -f

all: pre-build metre keys
	@echo Done.

pre-build: deps/unbound-1.6.1/configure
	git submodule update --init
	make -C deps/spiffing pre-build
	make -C deps/spiffing gen-ber/.marker
	cd deps/openssl && ./config --prefix=/usr/local --openssldir=/etc/ssl no-shared
	make -C deps/openssl
	cd deps/unbound-1.6.1 && ./configure CPPFLAGS=-I`pwd`/../../build/deps/libevent/include/ LDFLAGS=-L`pwd`/../openssl --disable-flto --enable-pie --disable-shared --with-ssl=`pwd`/../openssl --with-libevent=`pwd`/../libevent --with-libunbound-only
	mkdir -p build
	cd build && cmake ..
	cd build && make event_core_static
	make -C deps/unbound-1.6.1

deps/unbound-1.6.1.tar.gz:
	cd deps && wget http://unbound.nlnetlabs.nl/downloads/unbound-1.6.1.tar.gz

deps/unbound-1.6.1/configure: deps/unbound-1.6.1.tar.gz
	cd deps && tar zxvf unbound-1.6.1.tar.gz

keys:
	@echo [DNSSEC] . '=>' $@
	@dig . DNSKEY >$@

metre:
	mkdir -p build
	cd build && cmake ..
	make -C build
