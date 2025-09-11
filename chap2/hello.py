#!/usr/bin/python3

from bcc import BPF
import sys
import time

program = r"""
int hello(void *ctx){
    bpf_trace_printk("hello world!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

try:
    b.trace_print()
except KeyboardInterrupt:
    sys.exit(0)