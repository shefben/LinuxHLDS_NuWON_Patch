#!/bin/sh
#
exec 2>/dev/null
mkdir bin

exec 2>compile.log

icc 	-mia32 -O3 -fasm-blocks \
		-funroll-loops \
		-fomit-frame-pointer \
		-fno-rtti \
		-s \
		-fno-stack-protector \
		-falign-functions=2 \
		-Wno-unknown-pragmas \
		-static-intel -shared  \
		-static-libgcc \
		-fno-builtin \
		-fno-exceptions \
-I. main.cpp hook_utils.cpp utilities.cpp  \
-ldl -lm \
-o bin/neuwon.so
