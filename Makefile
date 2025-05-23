KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
BPF_CFLAGS = -g -Wall -O2 -target bpf -D__BPF__ -D__TARGET_ARCH_x86 \
  -isystem $(KERNEL_HEADERS)/arch/x86/include \
  -I$(KERNEL_HEADERS)/include \
  -I$(KERNEL_HEADERS)/include/uapi \
  -I$(KERNEL_HEADERS)/include/generated \
  -I$(KERNEL_HEADERS)/include/generated/uapi
CLANG ?= clang

all: monitor

# BPF object build rules
tcpmon.bpf.o: tcpmon.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

procmon.bpf.o: procmon.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

filemon.bpf.o: filemon.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Skeleton headers
tcpmon.skel.h: tcpmon.bpf.o
	bpftool gen skeleton $< > $@

procmon.skel.h: procmon.bpf.o
	bpftool gen skeleton $< > $@

filemon.skel.h: filemon.bpf.o
	bpftool gen skeleton $< > $@

# 최종 
monitor: main.c tcpmon.skel.h procmon.skel.h filemon.skel.h
	gcc -g -O2 -o $@ main.c -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.h monitor