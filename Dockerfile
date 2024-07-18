FROM ubuntu:latest AS cpp-build

RUN set -eux; \
   apt-get update; \
   DEBIAN_FRONTEND=noninteractive apt-get install --quiet --yes --no-install-recommends \
       build-essential \
       cmake \
       libevent-dev \
       libexpat-dev \
       libicu-dev \
       libspdlog-dev \
       libssl-dev \
       libunbound-dev \
       libunwind-dev \
       ninja-build \
       pkg-config \
   ; \
   apt-get clean; \
   rm -rf /var/lib/apt/lists/* ;

WORKDIR /app/

COPY deps src/deps

COPY cmake src/cmake
COPY include src/include
COPY src src/src
COPY tests src/tests
COPY CMakeLists.txt src/
COPY LICENSE src/
COPY metre.conf.yml src/

WORKDIR /app/build

RUN cmake \
        -DCMAKE_INSTALL_PREFIX=/app/install \
        -DCMAKE_BUILD_TYPE=Debug \
        -DVENDORED_DEPS=OFF \
        -DMETRE_BUILD_TESTS=OFF \
        -GNinja \
        ../src
RUN export CMAKE_BUILD_PARALLEL_LEVEL=4; \
    cmake --build . --target metre
RUN cmake --build . --target install

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

ENTRYPOINT ["/app/metre", "-d", "docker"]

EXPOSE 5269 5222 5275 5276
