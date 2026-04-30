#!/usr/bin/env bash

PCRE2_CFLAGS=""
PCRE2_LDFLAGS=""
if which pcre2-config > /dev/null && ! [[ $(pcre2-config --version) < "10.36" ]]; then
    PCRE2_CFLAGS="$(pcre2-config --cflags-posix) -DJULIE_USE_PCRE2"
    PCRE2_LDFLAGS="$(pcre2-config --libs-posix)"
fi

if [[ $(uname) == "Darwin" ]]; then
    WARN="-Wno-writable-strings -Wno-extern-c-compat"
else
    WARN="-Wno-write-strings -Wno-extern-c-compat"
fi

CPP_FLAGS="$(yed --print-cppflags) -std=c++20 -ftls-model=local-dynamic -Wall -Werror ${WARN}"

pids=()

gcc -o julie.o -c julie.c $(yed --print-cflags) -Wall -Werror &
pids+=($!)

for f in *.cpp; do
    g++ -o $(basename ${f} .cpp).o -c ${f} ${CPP_FLAGS} &
    pids+=($!)
done

for pid in "${pids[@]}"; do
    wait ${pid} || exit $?
done

g++ -o julie.so *.o $(yed --print-ldflags) ${PCRE2_LDFLAGS}
