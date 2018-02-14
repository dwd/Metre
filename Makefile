#!/usr/bin/make -f

all: pre-build metre keys
	@echo Done.

pre-build:
	git submodule update --init
	cd deps/openssl && ./config --prefix=/usr/local --openssldir=/etc/ssl no-shared
	make -C deps/openssl -j6

keys:
	@echo [DNSSEC] . '=>' $@
	@dig . DNSKEY >$@

metre:
	mkdir -p build
	cd build && cmake ..
	make -C build -j12

package: all
	make -C build package

dhparams: gen/dh1024.cc gen/dh2048.cc gen/dh4096.cc

gen/dh%.cc:
	./deps/openssl/apps/openssl dhparam -C -noout $* >$@
