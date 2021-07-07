#!/bin/sh

clang-11 -g -S -O2 -I ../ -I ../../linux/tools/lib/ -I ../../linux/include -emit-llvm -Xclang -disable-llvm-passes -c $1 -o - | llc-11 -march=bpf -filetype=obj -o $2
