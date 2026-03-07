# NekoFirewall

XDP/eBPF whitelist firewall for Linux, written in Rust with the [Aya](https://aya-rs.dev/) framework.  
All traffic is dropped by default. Only explicitly allowed IPs, ports, protocols, countries, and ASNs are permitted through.

## Build

Requires Linux with `clang`, `llvm`, `libelf-dev`, `linux-headers`, Rust stable + nightly, and `bpf-linker`.

```bash
cargo xtask build-ebpf   # eBPF program
cargo build --release     # userspace binary
# or both at once:
cargo xtask build
```

## Usage

```bash
# Run
sudo nf run -i eth0

# Allow / block rules (while firewall is running)
nf allow ip 1.2.3.4
nf allow port tcp 443
nf allow port udp 53
nf allow proto icmp
nf allow country US
nf allow asn 13335

nf block ip 1.2.3.4
nf block country CN

# List active rules
nf list

# Show connection tracking table
nf conntrack

# Monitor packet events in real time
nf monitor
```

## License
AGPLv3