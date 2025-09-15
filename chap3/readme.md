
```
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello

sudo bpftool  prog  show name hello --pretty

sudo bpftool map list
sudo bpftool map dump name hello.bss

sudo bpftool net attach xdp name hello dev lo


sudo bpftool net detach xdp  dev lo
```

```
yiji@m5:~/opensource/ebpf-tools/chap3$ sudo bpftool net attach xdp name hello dev enp0s5
libbpf: Kernel error message: virtio_net: Can't set XDP while host is implementing GRO_HW/CSUM, disable GRO_HW/CSUM first
Error: interface xdp attach failed: Operation not supported
yiji@m5:~/opensource/ebpf-tools/chap3$ sudo ethtool -K wlp2s0 rx off tx off tso off gso off
```


```
yiji@m5:~/opensource/ebpf-tools/chap3$ sudo ethtool -K enp0s5 rx off tx off tso off gso off
Actual changes:
tx-checksum-ip-generic: off
tx-generic-segmentation: off
tx-tcp-segmentation: off
tx-tcp-ecn-segmentation: off
tx-tcp6-segmentation: off
rx-checksum: on [requested off]
```