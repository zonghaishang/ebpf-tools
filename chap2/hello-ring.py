#!/usr/bin/python3

from bcc import BPF
import sys


program = r"""
BPF_RINGBUF_OUTPUT(output, 1);

struct event_t {
    char cmd[16];
    char filename[256];
    int dfd;
};

TRACEPOINT_PROBE(syscalls, sys_enter_openat){
    struct event_t event = {};

    event.dfd = args->dfd;
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    bpf_get_current_comm(&event.cmd, sizeof(event.cmd));

    bpf_trace_printk("File %d - %s", event.dfd, event.filename);
    bpf_trace_printk("     opened by: %s", event.cmd);

    output.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
"""

b = BPF(text=program)

def print_event(cpu, data, size):
    event = b["output"].event(data)
    print(f"{event.cmd.decode()} -> {event.filename.decode()}")

b["output"].open_ring_buffer(print_event)

try:
    while True:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    sys.exit(0)