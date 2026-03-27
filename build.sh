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

gcc -o julie.o  -c julie.c    $(yed --print-cflags) -Wall -Werror || exit $?
g++ -o plugin.o -c plugin.cpp $(yed --print-cppflags) -std=c++20 -ftls-model=local-dynamic -Wall -Werror ${WARN} || exit $?
g++ -o julie.so plugin.o julie.o $(yed --print-ldflags) ${PCRE2_LDFLAGS}
