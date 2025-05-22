#!/usr/bin/env bash

gcc -c -o julie.o julie.c $(yed --print-cflags) -Wall -Werror || exit $?
gcc -c -o plugin.o plugin.c $(yed --print-cflags) -Wall -Werror || exit $?
gcc -o julie.so julie.o plugin.o $(yed --print-cflags --print-ldflags)
