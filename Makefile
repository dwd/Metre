#!/usr/bin/make -f

all: pre-build metre keys
	@echo Done.

pre-build:
	git submodule update --recursive --init
	cd deps/openssl && ./config --prefix=/usr/local --openssldir=/etc/ssl no-shared
	make -C deps/openssl -j6

keys:
	@echo [DNSSEC] . '=>' $@
	@dig . DNSKEY >$@

metre:
	mkdir -p build
	#cd build && cmake .. -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_BUILD_TYPE=Debug
	cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug
	make -C build -j12

package: all
	make -C build package

apt-deps:
	apt-get install --quiet --no-install-recommends \
		cmake \
		libevent-dev \
		libicu-dev \
		libssl-dev \
		libunbound-dev \
		libunwind-dev \
		ninja-build \
		pkg-config

brew-deps:
	brew install \
		icu4c \
		libevent \
		ninja \
		openssl@1.1 \
		unbound

eclipse:
	mkdir -p ../metre-eclipse-build
	# -DCMAKE_CXX_COMPILER_ARG1 is a trick to make the Eclipse project generate with the correct C++ version flags
	cd ../metre-eclipse-build && cmake -G'Eclipse CDT4 - Ninja' -DCMAKE_CXX_COMPILER_ARG1="-std=c++17" -DVENDORED_DEPS=OFF ../metre
