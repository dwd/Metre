#!/bin/bash

set -x
LD_LIBRARY_PATH=.
DYLD_LIBRARY_PATH=.
ICU_DATA=/non-existent
mkdir -p /app/deps/
. /app/build/export-envs.sh
ldd /app/build/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}'
ldd /app/build/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}' \
    | grep '^/lib' \
    | xargs -I{} cp --parents {} '/app/deps/'
ldd /app/build/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}' \
    | grep -v '^/lib' \
    | xargs -I{} cp {} '/app/deps/lib/'
mkdir -p /app/ossl-modules
cp -pRv ${OPENSSL_MODULES}/* /app/ossl-modules/
mkdir -p /app/icu-data
echo ${ICU_DATA}
IFS=':'
for dir in ${ICU_DATA}; do
  [ -d ${dir} ] &&  cp -pRv ${dir}/* /app/icu-data/
done
exit 0