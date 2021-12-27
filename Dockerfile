FROM ubuntu:impish AS cpp-build

RUN set -eux; \
   apt-get update; \
   DEBIAN_FRONTEND=noninteractive apt-get install --quiet --yes --no-install-recommends \
       build-essential \
       cmake \
       googletest \
       libevent-dev \
       libexpat-dev \
       libicu-dev \
       libspdlog-dev \
       libssl-dev \
       libunbound-dev \
       ninja-build \
       pkg-config \
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

RUN set -eux; \
    mkdir build; \
    cd build; \
    cmake \
        -DCMAKE_INSTALL_PREFIX=/app/install \
        -DCMAKE_BUILD_TYPE=Debug \
        -DVENDORED_DEPS=OFF \
        -GNinja \
        ../src; \
    export CMAKE_BUILD_PARALLEL_LEVEL=4; \
    cmake --build .; \
    cmake --build . --target test; \
    cmake --build . --target install

RUN set -eux; \
    mkdir -p /app/deps/; \
    ldd /app/install/bin/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}' \
        | xargs -I{} cp --parents {} '/app/deps/'




FROM scratch

VOLUME /tmp

COPY --from=cpp-build /etc/passwd /etc/shadow /etc/
COPY --from=cpp-build /app/deps/ /

WORKDIR /app
COPY --from=cpp-build /app/install/bin/metre .

USER metre
ENTRYPOINT ["/app/metre", "-d", "docker"]

EXPOSE 5269 5222 5275 5276
