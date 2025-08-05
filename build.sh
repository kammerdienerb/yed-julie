#!/usr/bin/env bash

PCRE2_CFLAGS=""
PCRE2_LDFLAGS=""
if which pcre2-config > /dev/null && ! [[ $(pcre2-config --version) < "10.36" ]]; then
    PCRE2_CFLAGS="$(pcre2-config --cflags-posix) -DJULIE_USE_PCRE2"
    PCRE2_LDFLAGS="$(pcre2-config --libs-posix)"
fi

gcc -c -o julie.o julie.c $(yed --print-cflags) ${PCRE2_CFLAGS} -Wall -Werror || exit $?
gcc -c -o plugin.o plugin.c $(yed --print-cflags) ${PCRE2_CFLAGS} -Wall -Werror || exit $?
gcc -o julie.so julie.o plugin.o $(yed --print-cflags --print-ldflags) ${PCRE2_LDFLAGS}
