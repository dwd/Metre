FROM ubuntu:latest AS cpp-build

RUN set -eux; \
   apt-get update; \
   DEBIAN_FRONTEND=noninteractive apt-get install --quiet --yes --no-install-recommends \
       build-essential \
       cmake \
       libicu-dev \
       libunwind-dev \
       ninja-build \
       pkg-config \
       tcl \
        libtool \
        libtool-bin \
        automake \
      zlib1g-dev \
    doxygen \
    uuid-dev \
    libconfig++-dev \
    libidn2-dev \
   ; \
   apt-get clean; \
   rm -rf /var/lib/apt/lists/* ;

RUN adduser --system --home /var/cache/metre --shell /sbin/nologin metre

WORKDIR /app/

COPY deps src/deps

COPY cmake src/cmake
COPY gen src/gen
COPY include src/include
COPY src src/src
COPY tests src/tests
COPY CMakeLists.txt src/
COPY LICENSE src/
COPY metre.conf.xml src/
COPY build.sh src/

RUN cd src/deps && ls -l &&  find -name CMakeLists.txt

RUN set -eux; \
    cd src/deps/core/third-party/build; \
    sed -i 's/^.*\(buildPJSIP\)$/# \1/g' setup.sh; \
    sed -i 's/^.*\(buildGLOOX\)$/# \1/g' setup.sh; \
    sed -i 's/^.*\(buildAWS\)$/# \1/g' setup.sh; \
    sed -i 's/^.*\(buildJWTCPP\)$/# \1/g' setup.sh; \
    sed -i 's/^.*\(buildGoogleTest\)$/# \1/g' setup.sh; \
    ./setup.sh -l x86

RUN  cd src/deps/core/build/linux; \
     ./build_core.sh --no-fips --gw
RUN cd src/deps && tar zxvf core/build/linux/libarmourcore-x86-5.1.0.tgz

RUN set -eux; \
    mkdir build; \
    cd build; \
    cmake \
        -DCMAKE_INSTALL_PREFIX=/app/install \
        -DCMAKE_BUILD_TYPE=Debug \
        -DVENDORED_DEPS=ON \
        -GNinja \
        ../src; \
    export CMAKE_BUILD_PARALLEL_LEVEL=4; \
    cmake --build .; \
    cmake --build . --target install

RUN set -eux; \
    mkdir -p /app/deps/; \
    ldd /app/install/bin/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}' \
        | xargs -I{} cp --parents {} '/app/deps/'

RUN ./src/build.sh -c


FROM scratch

VOLUME /tmp

COPY --from=cpp-build /etc/passwd /etc/shadow /etc/
COPY --from=cpp-build /app/deps/ /

WORKDIR /app
COPY --from=cpp-build /app/install/bin/metre .

USER metre
ENTRYPOINT ["/app/metre", "-d", "docker"]

EXPOSE 5269 5222 5275 5276
