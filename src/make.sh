#!/bin/sh
gcc -fPIC -ggdb -D_GNU_SOURCE -I../include/ -c *.c
ar -rcs libelfmaster.a internal.o libelfmaster.o
cp libelfmaster.a /opt/elfmaster/lib/
cp ../include/libelfmaster.h /opt/elfmaster/include

