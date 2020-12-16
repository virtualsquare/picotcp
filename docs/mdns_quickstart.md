# mDNS getting started

## Setting up environment

### Create TAP interface

```
sudo ip tuntap add mode tap name tap0
sudo ip addr add 10.0.0.254/24 dev tap0
sudo ip link set tap0 up
```

### Connect a `vde_switch`

```
vde_switch -hub -sock /tmp/vde0.ctl -m 777 -M /tmp/pico.mgmt -daemon
```

### Run picoapp mDNS applet

```
./build/test/picoapp.elf --vde vde0:/tmp/vde0.ctl:10.0.0.1:255.255.255.0:10.0.0.254: --app mdns:foo.local:bar.local:
```

### Test

```
$ ping foo.local
PING foo.local (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1 (10.0.0.1): icmp_seq=1 ttl=64 time=1.73 ms
64 bytes from 10.0.0.1 (10.0.0.1): icmp_seq=2 ttl=64 time=1.61 ms
64 bytes from 10.0.0.1 (10.0.0.1): icmp_seq=3 ttl=64 time=1.82 ms
```

