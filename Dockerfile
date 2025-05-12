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
RUN conan remote add nexus https://nexus.cridland.io/repository/dwd-conan/
RUN conan remote add nexus-proxy https://nexus.cridland.io/repository/conan-proxy/
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
# COPY conan.lock src/

WORKDIR /app/src

RUN conan install . --build=missing -s build_type=RelWithDebInfo --deployer=runtime_deploy --deployer-folder=/app/lib
#--lockfile=conan.lock

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

RUN /app/build/metre -d aidsa || true

RUN grep -ash ^export /app/build/conan/build/RelWithDebInfo/generators/conanrun*.sh >/app/build/export-envs.sh; cat /app/build/export-envs.sh

COPY copy-deps.sh .
RUN bash copy-deps.sh

RUN set -eux; \
    mkdir -p /app/deps/; \
    ldd /app/build/metre; \
    ls -l /app/deps/

RUN find /app/deps/ -type f

FROM scratch

ENV METRE_CONF_YML="/tmp/metre.conf.yml"

VOLUME /tmp

COPY --from=cpp-build /etc/passwd /etc/shadow /etc/
COPY --from=cpp-build /app/deps/ /
COPY --from=cpp-build /app/ossl-modules /app/ossl-modules
ENV OPENSSL_MODULES=/app/ossl-modules
COPY --from=cpp-build /app/icu-data /app/icu-data
ENV ICU_DATA=/app/icu-data

WORKDIR /app
COPY --from=cpp-build /app/build/metre /app/metre

#For the healthcheck to work and be configurable, we pretty much have to stipulate where the config file is, so we rely on Metre picking up the environment variable.
HEALTHCHECK CMD ["/app/metre", "-d", "healthcheck"]
ENTRYPOINT ["/app/metre", "-d", "docker"]

EXPOSE 5269 5222 5275 5276
