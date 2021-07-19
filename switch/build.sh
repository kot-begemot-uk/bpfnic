#!/bin/sh

clang-11 -fno-stack-protector  -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
                -Wno-gnu-variable-sized-type-not-at-end \
                -Wno-address-of-packed-member -Wno-tautological-compare \
                -Wno-unknown-warning-option \
		-g -S -O2 -I ../ -I ../../linux/tools/lib/ -I ../../linux/include -emit-llvm -Xclang -disable-llvm-passes -c $1 -o - |\
		opt-11 -O2 -mtriple=bpf-pc-linux | llvm-dis-11 |\
		llc-11 -march=bpf -filetype=obj -o $2
