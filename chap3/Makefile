TARGET = hello hello-func

ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PYONY: all

# all: $(TARGET)

# $(TARGET): %: %.bpf.o

# %.bpf.o: %.bpf.c
# 	clang \
# 		-target bpf \
# 		-I/usr/include/$(shell uname -m)-linux-gnu \
# 		-g \
# 		-O2 -o $@ -c $<

%: %.c %.skel.h
	gcc -Wall -o $@ $< -L../libbpf/src -l:libbpf.a -lelf -lz

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

%.bpf.o: %.bpf.c vmlinux.h
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm $(TARGET)