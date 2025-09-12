TARGET = hello

.PYONY: all

all: $(TARGET)

$(TARGET): %: %.bpf.o

%.bpf.o: %.bpf.c
	clang \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -o $@ -c $<