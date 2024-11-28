FROM ubuntu:24.04 AS cpp-build

RUN apt-get update; \
   DEBIAN_FRONTEND=noninteractive apt-get install --quiet --yes --no-install-recommends \
       build-essential \
       cmake \
       ninja-build \
       pkg-config \
       python3 \
       python3-pip \
       flex yacc libexpat-dev

RUN pip install conan --break-system-packages

RUN conan profile detect
RUN echo "[settings]" >$(conan profile path default)
RUN echo "arch=x86_64" >>$(conan profile path default)
RUN echo "build_type=Release" >>$(conan profile path default)
RUN echo "compiler=gcc" >>$(conan profile path default)
RUN echo "compiler.cppstd=gnu23" >>$(conan profile path default)
RUN echo "compiler.libcxx=libstdc++11" >>$(conan profile path default)
RUN echo "compiler.version=13" >>$(conan profile path default)
RUN echo "os=Linux" >>$(conan profile path default)

RUN conan remote remove conancenter
RUN conan remote add jekyll http://jekyll.cridland.io:9300/ --insecure
WORKDIR /app/
RUN touch seven

COPY deps src/deps

COPY cmake src/cmake
COPY include src/include
COPY src src/src
COPY tests src/tests
COPY CMakeLists.txt src/
COPY LICENSE src/
COPY metre.conf.yml src/
COPY conanfile.py src/
COPY conan_provider.cmake src/
COPY conandata.yml src/
COPY conan.lock src/

WORKDIR /app/src

RUN conan install . --build=missing -s build_type=RelWithDebInfo --deployer=runtime_deploy --deployer-folder=/app/lib --lockfile=conan.lock

WORKDIR /app/build

RUN cmake \
        -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="conan_provider.cmake" \
        -DCMAKE_INSTALL_PREFIX=/app/install \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DMETRE_BUILD_TESTS=OFF \
        -DMETRE_SENTRY=ON \
        -GNinja \
        ../src
RUN cmake --build . --target metre
RUN cmake --build . --target install

RUN /app/build/metre -d aidsa || true

RUN set -eux; \
    mkdir -p /app/deps/; \
    LD_LIBRARY_PATH=/app/deps/usr/lib ldd /app/install/bin/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}' \
        | xargs -I{} cp --parents {} '/app/deps/'

RUN set -eux; \
    mkdir -p /app/deps/; \
    ldd /app/install/bin/metre

RUN find /app/deps/ -type f

FROM scratch

ENV METRE_CONF_YML="/tmp/metre.conf.yml"

VOLUME /tmp

COPY --from=cpp-build /etc/passwd /etc/shadow /etc/
COPY --from=cpp-build /app/deps/ /

WORKDIR /app
COPY --from=cpp-build /app/install/bin/metre .

#For the healthcheck to work and be configurable, we pretty much have to stipulate where the config file is, so we rely on Metre picking up the environment variable.
HEALTHCHECK CMD ["/app/metre", "-d", "healthcheck"]
ENTRYPOINT ["/app/metre", "-d", "docker"]

EXPOSE 5269 5222 5275 5276
