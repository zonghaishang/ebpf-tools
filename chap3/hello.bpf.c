#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

int counter = 0;

SEC("xdp")
int hello2(struct xdp_md *ctx) {
    bpf_printk("hello world2 %d", counter);
    counter++;
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";