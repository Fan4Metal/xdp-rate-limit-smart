# xdp-rate-limit-smart

**English** · [Русский](README.ru.md)

An XDP filter for Ubuntu that accounts for inbound IPv4 traffic per source IP and
for the interface as a whole. A small Python daemon adds a **smart mode**: when
the total inbound traffic crosses a global threshold, it bans only the IPs that
individually exceed a per-source threshold.

IPv6 is passed through without filtering in this version — see
[Limitations & threat model](#limitations--threat-model).

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Configuration](#configuration)
- [Smart mode](#smart-mode)
- [Direct per-IP limit](#direct-per-ip-limit)
- [Logs](#logs)
- [Status & diagnostics](#status--diagnostics)
- [Dry-run](#dry-run)
- [Stop & uninstall from an interface](#stop--uninstall-from-an-interface)
- [Build from source](#build-from-source)
- [Important notes](#important-notes)
- [Limitations & threat model](#limitations--threat-model)
- [Accounting of banned traffic](#accounting-of-banned-traffic)

## Features

- XDP program in C.
- Loaded through a tiny libbpf loader — no BCC.
- Per-CPU counters (no cross-core cache-line contention, no atomics).
- Global interface stats: Mbps and PPS.
- Per-source-IPv4 stats.
- **Smart global mode** ([details](#smart-mode)):
  - total traffic above `global_mbps_limit` / `global_pps_limit`;
  - bans IPs above `smart_ban_min_mbps` / `smart_ban_min_pps`.
- Optional direct per-IP limit via `per_ip_mbps_limit` / `per_ip_pps_limit`
  ([details](#direct-per-ip-limit)).
- Temporary bans with automatic unban.
- IPv4 and CIDR whitelist, e.g. `1.2.3.4` or `10.0.0.0/24`.
- systemd service.

## How it works

The fast path and the policy are split:

- The **XDP program** ([`src/xdp_rate_limit.bpf.c`](src/xdp_rate_limit.bpf.c))
  only counts bytes/packets and drops sources listed in the blacklist map. It is
  loaded and its maps are pinned by the **loader**
  ([`src/xdp_loader.c`](src/xdp_loader.c)).
- The **Python daemon** ([`src/xdp_rate_daemon.py`](src/xdp_rate_daemon.py)) reads
  the pinned maps every `interval_seconds`, computes rates, and decides who to ban.

Everything is wired together by the systemd template unit
([`systemd/xdp-rate-limit@.service`](systemd/xdp-rate-limit@.service)), which calls
the wrapper ([`src/xdp-rate-limit-wrapper`](src/xdp-rate-limit-wrapper)).

> For a detailed, component-by-component walkthrough of the internals — the XDP
> packet path, the BPF maps, the loader lifecycle, and the daemon's decision loop —
> see **[Architecture & mechanism](docs/architecture.md)**.

## Requirements

- Linux kernel ≥ 4.10 (needed for `LRU_PERCPU_HASH`; any current Ubuntu qualifies).
- Root privileges and a mountable bpffs at `/sys/fs/bpf`.
- Build toolchain (installed automatically by [`install.sh`](install.sh)):
  `clang`, `llvm`, `gcc`, `make`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`,
  `iproute2`, `python3`.

## Install

```bash
sudo ./install.sh eth0
```

Where `eth0` is the server's external interface. Find yours with:

```bash
ip -br link
ip route get 1.1.1.1
```

The installer copies a default [`etc/config.json`](etc/config.json) to
`/etc/xdp-rate-limit/config.json` and, if it detects your current SSH client,
adds that IP to the whitelist automatically. Always double-check the whitelist —
see [Important notes](#important-notes).

## Configuration

```bash
sudo nano /etc/xdp-rate-limit/config.json
```

Aggressive profile — global threshold 5 Mbps, ban IPs from 2 Mbps:

```json
{
  "interval_seconds": 1.0,

  "smart_global_enabled": true,
  "global_mbps_limit": 5.0,
  "global_pps_limit": 0,

  "smart_ban_min_mbps": 2.0,
  "smart_ban_min_pps": 0,

  "per_ip_mbps_limit": 0,
  "per_ip_pps_limit": 0,

  "ban_seconds": 300,
  "extend_ban_on_repeat": true,
  "max_bans_per_tick": 50,

  "whitelist": [
    "127.0.0.1",
    "YOUR_SSH_IP"
  ],

  "dry_run": false
}
```

Milder profile — global threshold 10 Mbps, ban IPs from 5 Mbps:

```json
{
  "smart_global_enabled": true,
  "global_mbps_limit": 10.0,
  "smart_ban_min_mbps": 5.0,
  "per_ip_mbps_limit": 0,
  "ban_seconds": 300,
  "whitelist": ["127.0.0.1", "YOUR_SSH_IP"]
}
```

Before applying, check that the JSON is valid — otherwise the daemon keeps the
old config and logs `tick failed`:

```bash
python3 -m json.tool /etc/xdp-rate-limit/config.json >/dev/null && echo "JSON OK"
```

The daemon **hot-reloads** the file on `mtime` change — no restart needed, new
values apply within `interval_seconds` (a `Config loaded: ...` line appears in the
log). The whitelist is re-synced automatically too. Force a restart if you want:

```bash
sudo systemctl restart xdp-rate-limit@eth0
```

## Smart mode

### The idea

A plain per-IP limit punishes any heavy client, even when the server is idle and
nobody is hurt. Smart mode instead asks two questions in order, and bans an IP
**only if both are true**:

1. **Is the interface actually under pressure?** — the *global gate*: total inbound
   traffic must cross `global_mbps_limit` (or `global_pps_limit`).
2. **Is this specific IP a meaningful part of that pressure?** — the *per-source
   gate*: the IP's own rate must cross `smart_ban_min_mbps` (or `smart_ban_min_pps`).

So while the link is calm, even a fairly busy client is left alone. Only once the
aggregate becomes a problem does the daemon start banning the biggest contributors.
This is the key difference from the [direct per-IP limit](#direct-per-ip-limit),
which fires unconditionally.

### How a tick works

Every `interval_seconds` the daemon:

1. Reads global and per-IP counters and converts them to Mbps/PPS over the elapsed
   interval.
2. Evaluates the global gate. If it is **not** crossed (or `smart_global_enabled`
   is `false`), no smart bans happen this tick.
3. If it **is** crossed, every source above the per-source gate becomes a ban
   candidate (`reason=smart-global`).
4. Candidates are sorted by rate (highest first) and banned, up to
   `max_bans_per_tick` per tick, for `ban_seconds` each.
5. Bans auto-expire; the daemon removes them and logs `UNBAN`.

A threshold with value `0` is **disabled** — e.g. `global_pps_limit: 0` means only
Mbps is used for the global gate. A limit triggers when the measured value is
`>=` it.

### Parameters

| Key | Meaning |
| --- | --- |
| `smart_global_enabled` | Master switch for smart mode. |
| `global_mbps_limit` / `global_pps_limit` | Global gate: interface totals that must be exceeded before any smart ban. `0` disables that metric. |
| `smart_ban_min_mbps` / `smart_ban_min_pps` | Per-source gate: only IPs above this are banned once the global gate is open. `0` disables that metric. |
| `ban_seconds` | Ban duration; `0` = permanent until removed. |
| `extend_ban_on_repeat` | If `true`, a still-offending IP has its ban extended instead of left to expire. |
| `max_bans_per_tick` | Safety cap on how many IPs can be banned per interval. |
| `interval_seconds` | Measurement/decision interval. |

### Choosing values

1. Run with `"dry_run": true` (see [Dry-run](#dry-run)) for a while and watch the
   periodic summary in the [logs](#logs) to learn your normal `global=...Mbps/...pps`
   and the typical top-IP rates.
2. Set `global_mbps_limit` a bit **above** your normal peak — you want smart mode to
   engage during an anomaly, not during ordinary busy periods.
3. Set `smart_ban_min_mbps` **above** what a single legitimate client normally sends,
   so real users are never candidates even when the global gate opens.
4. Prefer PPS gates (`global_pps_limit` / `smart_ban_min_pps`) for packet-flood /
   small-packet attacks, and Mbps gates for bandwidth-heavy floods. You can set both;
   either metric crossing is enough.
5. Keep your admin/SSH IP in the `whitelist` — whitelisted IPs are never candidates
   (see [Important notes](#important-notes)).

### Worked examples

Global gate **open** (total 8 Mbps ≥ 5 Mbps limit), per-source gate at 2 Mbps:

```text
Total inbound on eth0 = 8 Mbps   (global_mbps_limit = 5  -> gate OPEN)
smart_ban_min_mbps = 2

1.1.1.1 = 3.2 Mbps  -> ban   (over per-source gate)
2.2.2.2 = 2.4 Mbps  -> ban   (over per-source gate)
3.3.3.3 = 0.4 Mbps  -> kept  (under per-source gate)
```

Global gate **closed** — nothing is banned, even a busy client:

```text
Total inbound on eth0 = 3 Mbps   (global_mbps_limit = 5  -> gate CLOSED)
smart_ban_min_mbps = 2

1.1.1.1 = 2.6 Mbps  -> kept   (server isn't under pressure)
```

If you *do* want that 2.6 Mbps client banned regardless of the global level, that is
exactly the job of the [direct per-IP limit](#direct-per-ip-limit) — the two rules
work together: direct limits are always checked, smart bans only when the global
gate is open.

> **Self-correcting by design.** Banned traffic is dropped *before* accounting, so a
> banned IP stops counting toward the global total. After the worst offenders are
> banned, the interface total often falls back below `global_mbps_limit`, the gate
> closes, and smart mode stops banning further — see
> [Accounting of banned traffic](#accounting-of-banned-traffic).

## Direct per-IP limit

To always ban an IP, even without exceeding the global limit:

```json
{
  "per_ip_mbps_limit": 5.0,
  "per_ip_pps_limit": 0
}
```

Any IP above 5 Mbps is then banned immediately.

## Logs

```bash
journalctl -u xdp-rate-limit@eth0 -f
```

Ban example:

```text
BAN 1.2.3.4 for 300s: 3.214 Mbps, 4200 pps, reason=smart-global
```

Periodic summary:

```text
iface=eth0 global=7.531Mbps/12000pps smart_exceeded=True active_bans=2 top=[1.2.3.4=3.21Mbps/4200pps]
```

## Status & diagnostics

Service state. Watch that `NRestarts` **does not grow** — a rising counter means a
restart loop (the service crashes and systemd brings it back up):

```bash
systemctl status xdp-rate-limit@eth0
systemctl show -p NRestarts -p ActiveState xdp-rate-limit@eth0
```

What is actually attached to the interface (there should be a single `xdp` program):

```bash
sudo bpftool net show dev eth0
ip -d link show eth0 | grep -i xdp
```

Live log with bans and the periodic summary:

```bash
journalctl -u xdp-rate-limit@eth0 -f
```

Active bans and the daemon's scan size (number of source IPs in the stats map):

```bash
# current blacklist
sudo bpftool map dump pinned /sys/fs/bpf/xdp-rate-limit/eth0/blacklist_map
# how many entries in the per-source stats
sudo bpftool map dump pinned /sys/fs/bpf/xdp-rate-limit/eth0/stats_map | grep -c '"key"'
```

How much CPU the daemon itself uses right now:

```bash
PID=$(systemctl show -p MainPID --value xdp-rate-limit@eth0)
top -b -n2 -d1 -p "$PID" | tail -5
```

If the service is stuck in a restart loop or an orphaned XDP program is left on the
interface, reset the counter and restart. `load` is self-healing: on start it
detaches its own leftover instance and re-attaches, so usually this is enough:

```bash
sudo systemctl reset-failed xdp-rate-limit@eth0
sudo systemctl restart xdp-rate-limit@eth0
```

## Dry-run

To test without banning for real:

```json
{
  "dry_run": true
}
```

Logs show `DRY-RUN BAN`, but IPs are not added to the XDP blacklist.

## Stop & uninstall from an interface

Stop:

```bash
sudo systemctl stop xdp-rate-limit@eth0
```

Disable autostart:

```bash
sudo systemctl disable xdp-rate-limit@eth0
```

Force-detach XDP if needed:

```bash
sudo /usr/local/sbin/xdp-rate-loader unload eth0 /sys/fs/bpf/xdp-rate-limit/eth0
```

`unload` only removes **its own** program (matched by the name `xdp_rate_limiter`),
including an orphan left behind after its pins were lost. It never touches a foreign
XDP program — to remove one anyway, add `--force` (or `XDP_FORCE=1` in the
environment):

```bash
sudo /usr/local/sbin/xdp-rate-loader unload eth0 /sys/fs/bpf/xdp-rate-limit/eth0 --force
```

## Build from source

To compile and check locally without deploying to a server, use the
[`Makefile`](Makefile) (outputs go to `./build`):

```bash
make            # compile the BPF object + loader
make pycheck    # byte-compile the Python daemon
make verify     # dump the compiled BPF program (needs bpftool)
make clean
```

The BPF object and loader build on Linux only; `make pycheck` runs anywhere with
`python3`.

## Important notes

1. Add your SSH/admin IP to the `whitelist`, or you may ban yourself.
2. XDP acts on the interface's inbound traffic.
3. Mbps is measured by packet size at XDP ingress — close to the interface rate,
   but not identical to your provider's figures.
4. Whitelisted IPs are neither accounted nor banned — see
   [Accounting of banned traffic](#accounting-of-banned-traffic).
5. With `ban_seconds = 0`, a ban is permanent until its map entry is removed or
   the service is restarted/unloaded.

## Limitations & threat model

This tool targets "noisy neighbours" and moderate spikes from a small number of
real sources. What it does **not** do:

1. **Source-IP spoofing / volumetric floods.** `stats_map` is a per-CPU LRU hash.
   Under a flood from randomized spoofed addresses, entries are evicted (LRU) and
   recreated from zero, so no single IP ever accumulates enough delta to hit the
   ban threshold. This is inherent to "account by source IP": against a classic
   spoofed flood it is blind. Use an upstream scrubber / BGP blackhole / stateful
   protection instead.
2. **IPv6 is passed through entirely** — no accounting, no bans. An IPv6 attacker
   bypasses the filter. If you don't need IPv6, block it separately at the firewall.
3. **Reaction is not instant.** A ban is issued from the per-interval delta
   (`~1 s`), and a brand-new IP is only caught on its second tick. Micro-bursts
   shorter than the interval slip through.
4. **Blacklist capacity** — `blacklist_map` holds 262144 entries. On overflow the
   daemon logs an error and stops adding new bans (existing ones keep working).
5. **Mbps is measured at XDP ingress** — close to, but not identical to, your
   provider's numbers.

## Accounting of banned traffic

Active blacklisted IPv4 sources are checked before updating `global_stats_map` and
`stats_map`. Therefore packets that are already being dropped by XDP do not count
toward `global_mbps_limit`, do not appear in the top-IP candidates for smart bans,
and do not keep the smart mode triggered by themselves.

The whitelist is still checked first, so whitelisted admin addresses bypass both
the blacklist and accounting.
