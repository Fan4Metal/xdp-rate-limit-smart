# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An XDP-based inbound IPv4 rate limiter for Ubuntu/Linux. An eBPF program on the
NIC counts ingress bytes/packets per source IP and globally, and drops IPs listed
in a blacklist map. A Python daemon reads the pinned maps every tick, computes
rates, and decides who to ban. IPv6 is passed through unfiltered.

The code only runs on Linux (BPF object + loader need `clang`/`libbpf`); this repo
is developed on Windows, so most work here is editing + `make pycheck`, with real
compilation/testing happening on a Linux box or server.

## Commands

```bash
make            # compile BPF object + loader into ./build (Linux only)
make bpf        # BPF object only
make loader     # userspace loader only
make pycheck    # byte-compile the Python daemon (runs on any OS with python3)
make verify     # dump the compiled BPF program (needs bpftool)
make clean

sudo ./install.sh eth0   # full install: apt deps, compile, install, enable systemd unit
```

There is no test suite. `make pycheck` (`python3 -m py_compile`) is the only check
that runs cross-platform; use it after editing the daemon.

Runtime inspection on a deployed host:
```bash
journalctl -u xdp-rate-limit@eth0 -f
sudo bpftool net show dev eth0
sudo bpftool map dump pinned /sys/fs/bpf/xdp-rate-limit/eth0/blacklist_map
```

## Architecture

For a full component-by-component walkthrough, see
[docs/architecture.md](docs/architecture.md) (RU: [docs/architecture.ru.md](docs/architecture.ru.md)).
The summary below is the fast version.

Fast path (packet decisions) and policy (who to ban) are deliberately split across
three processes. The five components chain like this:

```
systemd xdp-rate-limit@IFACE.service
  └─ src/xdp-rate-limit-wrapper IFACE start
       ├─ src/xdp_loader.c  →  loads xdp_rate_limit.bpf.o, attaches XDP, pins maps
       └─ exec src/xdp_rate_daemon.py  →  reads pinned maps, bans/unbans
```

- **[src/xdp_rate_limit.bpf.c](src/xdp_rate_limit.bpf.c)** — the eBPF/XDP program
  (`xdp_rate_limiter`). Per packet, in order: parse eth (incl. up to 2 VLAN tags),
  IPv4 only; **whitelist** (LPM trie) → PASS; **blacklist** (hash) → DROP;
  otherwise bump per-CPU global and per-source counters, PASS. Four maps:
  `stats_map` (LRU per-CPU hash, keyed by network-order IPv4), `global_stats_map`
  (per-CPU array), `blacklist_map` (hash, value = `expires_ns`), `whitelist_lpm_map`
  (LPM trie).

- **[src/xdp_loader.c](src/xdp_loader.c)** — minimal libbpf loader. `load`/`unload`
  subcommands. Attaches native (DRV) then falls back to generic (SKB). Pins maps
  and the program to `PIN_DIR`. **Self-healing**: on `load` it first detaches any
  leftover instance of *its own* program (matched by name `xdp_rate_limiter`) and
  wipes stale pins so restarts are idempotent. It never touches a foreign XDP
  program unless `--force` / `XDP_FORCE=1`.

- **[src/xdp_rate_daemon.py](src/xdp_rate_daemon.py)** — the policy engine. No BCC;
  talks to BPF maps via raw `bpf(2)` syscalls through `ctypes` (see `BpfMap`).
  Every `interval_seconds` it reads counter deltas, converts to Mbps/PPS, and bans.
  Two independent rules: **direct per-IP** (always fires) and **smart-global** (bans
  top sources only when the interface total crosses a global gate). Config
  hot-reloads on file `mtime` change. Bans carry an expiry and auto-unban.

- **[src/xdp-rate-limit-wrapper](src/xdp-rate-limit-wrapper)** — glue script:
  mounts bpffs, calls the loader, then `exec`s the daemon. `stop` unloads.

- **[systemd/xdp-rate-limit@.service](systemd/xdp-rate-limit@.service)** — template
  unit; `%i` is the interface. `ExecStopPost` runs the wrapper `stop` to detach XDP.

### Cross-component contracts (edit these together)

Because the C program, the loader, and the Python daemon are separate binaries that
share pinned maps by memory layout, several things must stay in lockstep:

- **Map key/value sizes** are hardcoded in the daemon (`BpfMap(..., key_size,
  value_size, percpu=...)` in `XdpRateDaemon.__init__`). If you change a struct in
  the `.bpf.c` file (e.g. `traffic_stats`, `ban_value`, `ipv4_lpm_key`), update the
  matching `BpfMap` sizes and the `struct.pack`/`unpack` format strings.
- **Byte order matters**: IPv4 keys are stored in *network* order (`inet_aton`);
  `ipv4_lpm_key` is *little-endian* `prefixlen` + network-order address; counters
  and `expires_ns` are little-endian u64. See `whitelist_key`, `unpack_stats`.
- **Per-CPU maps** return one value block per *possible* CPU (`/sys/.../cpu/possible`,
  not online count), each padded to 8 bytes. `unpack_stats` sums the blocks; don't
  assume a single block.
- **Program name** `xdp_rate_limiter` is the identity used by the loader to
  recognize its own attachment (`XDP_PROG_NAME`). Renaming the `SEC("xdp")` function
  breaks self-healing detach — change both `.bpf.c` and `xdp_loader.c`.
- **`bpf(2)` command constants** in the daemon are the raw syscall numbers
  (`BPF_OBJ_GET = 7`, etc.) — a past bug used the wrong value. Don't "fix" these to
  other numbers.

### Ban accounting invariant

The XDP program checks the blacklist **before** touching the counters, so
already-dropped traffic does not count toward the global total or the top-IP list.
This makes smart mode self-correcting: once the worst offenders are banned, the
interface total falls back under the gate and banning stops. Preserve this ordering
if you edit the packet path.

## Known limitations (by design)

- **IPv6 is passed through entirely** — no accounting, no bans.
- **Spoofed/randomized-source floods defeat it**: `stats_map` is LRU, so entries for
  transient spoofed IPs are evicted before any single IP accumulates a bannable
  delta. This tool targets noisy real clients, not volumetric DDoS.
- Reaction latency ≈ one interval; a new IP is only caught on its second tick.
- `blacklist_map` caps at 262144 entries; on overflow the daemon logs and stops
  adding bans.

## Conventions

- Keep everything LF (enforced via `.gitattributes`) — CRLF breaks the shell
  scripts, systemd unit, and BPF sources on Linux.
- Config lives at `/etc/xdp-rate-limit/config.json` in production; the repo default
  is [etc/config.json](etc/config.json). Whitelist entries accept `IP` or `CIDR`.
- README.md (English) and README.ru.md (Russian) are kept in sync — update both
  when documenting user-facing behavior.
