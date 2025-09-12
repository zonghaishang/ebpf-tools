#!/usr/bin/python3

from bcc import BPF
import sys

program = r"""
struct data_t {
    u32 pid;
    u64 uid;
    char cmd[16];
    char msg[12];
};

BPF_PERF_OUTPUT(events);

int hello(void *ctx) {
    struct data_t data = {};

    char msg[12] = "hello world";
    msg[11] = '\0';

    data.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.cmd, sizeof(data.cmd));
    bpf_probe_read_kernel(&data.msg, sizeof(data.msg), msg);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"pid:{event.pid} uid:{event.uid} cmd:{event.cmd.decode()} msg:{event.msg.decode()}")

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    sys.exit(0)