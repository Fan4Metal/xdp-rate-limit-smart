# Architecture & mechanism

[English](architecture.md) · [Русский](architecture.ru.md)

A detailed walkthrough of how `xdp-rate-limit-smart` works internally: the packet
path in the kernel, the BPF maps that connect the pieces, the loader lifecycle,
and the daemon's decision loop. For install/usage see the [README](../README.md);
for the terse contributor summary see [CLAUDE.md](../CLAUDE.md).

## Contents

- [Design in one picture](#design-in-one-picture)
- [Why the split](#why-the-split)
- [The BPF maps](#the-bpf-maps)
- [Data plane: the XDP program](#data-plane-the-xdp-program)
- [The loader](#the-loader)
- [Control plane: the daemon](#control-plane-the-daemon)
- [The two ban rules](#the-two-ban-rules)
- [Ban lifecycle](#ban-lifecycle)
- [Reading counters correctly](#reading-counters-correctly)
- [Cross-component contracts](#cross-component-contracts)
- [systemd wiring](#systemd-wiring)

## Design in one picture

```
                         packets in
                             │
        ┌────────────────────▼─────────────────────┐
        │  DATA PLANE  (kernel, per packet)         │
        │  src/xdp_rate_limit.bpf.c → xdp_rate_limiter
        │                                           │
        │   whitelist? ─yes→ PASS (no accounting)   │
        │   blacklist & not expired? ─yes→ DROP     │
        │   else: count (global + per-source), PASS │
        └───────┬───────────────────────────┬───────┘
                │ pinned maps (bpffs)        │
   stats_map ───┤  global_stats_map ─────────┤─── blacklist_map ── whitelist_lpm_map
      (reads)   │      (reads)               │      (writes)         (writes)
                ▼                            ▼
        ┌───────────────────────────────────────────┐
        │  CONTROL PLANE  (userspace, every ~1 s)    │
        │  src/xdp_rate_daemon.py                    │
        │                                            │
        │   read counters → deltas → Mbps/PPS        │
        │   decide who to ban (2 rules)              │
        │   write/expire entries in blacklist_map    │
        └────────────────────────────────────────────┘

   Loaded/attached/pinned by:  src/xdp_loader.c   (load | unload)
   Wired together by:          systemd + src/xdp-rate-limit-wrapper
```

The kernel program is the **data plane**: it runs on every packet and must be
tiny and fast, so it only *counts* and *drops*. The Python program is the
**control plane**: it runs once per interval, does all the arithmetic and policy,
and communicates decisions back to the kernel purely by editing a map.

## Why the split

Putting the policy in the XDP program would mean recomputing rates and thresholds
in the hot path on every packet — expensive and hard to change. Instead:

- The XDP program keeps **raw cumulative counters** (bytes/packets), which is
  almost free: a couple of map lookups and additions per packet.
- The daemon samples those counters on a timer, computes **rates from deltas**,
  and applies human-tunable policy (thresholds, ban durations, whitelist).

The only shared state is the four pinned maps. Neither side calls the other; they
communicate entirely through map contents. This is why map **layout** (sizes and
byte order) is a hard contract — see [Cross-component contracts](#cross-component-contracts).

## The BPF maps

All four are declared in [`src/xdp_rate_limit.bpf.c`](../src/xdp_rate_limit.bpf.c)
and pinned under `/sys/fs/bpf/xdp-rate-limit/<iface>/` by the loader.

| Map | Type | Key | Value | Written by | Read by |
| --- | --- | --- | --- | --- | --- |
| `stats_map` | `LRU_PERCPU_HASH` (262144) | `u32` src IPv4, **network order** | `traffic_stats {u64 bytes, u64 packets}` | XDP | daemon |
| `global_stats_map` | `PERCPU_ARRAY` (1) | `u32` index `0` | `traffic_stats` | XDP | daemon |
| `blacklist_map` | `HASH` (262144) | `u32` src IPv4, network order | `ban_value {u64 expires_ns}` | daemon | XDP |
| `whitelist_lpm_map` | `LPM_TRIE` (4096) | `ipv4_lpm_key {u32 prefixlen, u32 addr}` | `u8` | daemon | XDP |

Two design choices worth calling out:

- **Per-CPU** (`stats_map`, `global_stats_map`): each CPU core bumps its own
  private copy of the counter, so there is no cross-core cache-line bouncing and
  no need for atomic operations in the packet path. The daemon **sums across all
  CPUs** when it reads.
- **LRU** (`stats_map`): the per-source table is bounded at 262144 entries; when
  full, the kernel evicts the least-recently-used entry to make room. This keeps
  memory bounded under a flood of many distinct source IPs — but it is also
  exactly why spoofed/randomized-source floods defeat the accounting (an evicted
  entry restarts from zero and never accumulates a bannable delta).

## Data plane: the XDP program

`xdp_rate_limiter` runs at the earliest point in the network stack (the NIC
driver, or the generic hook as a fallback). For every frame it executes this
fixed decision sequence:

```
1. Parse Ethernet header (bounds-checked).
   ├─ Follow up to 2 VLAN tags (802.1Q / 802.1AD).
   └─ If the final EtherType is not IPv4  → XDP_PASS   (IPv6, ARP, … untouched)

2. Parse the IPv4 header (bounds-checked). src = iph->saddr  (network order)

3. Whitelist lookup (LPM /32 exact for a plain IP, or any covering CIDR):
   └─ hit → XDP_PASS  immediately.  No accounting, no ban check.

4. Blacklist lookup:
   └─ hit AND (expires_ns == 0  OR  expires_ns > now) → XDP_DROP
      (expires_ns == 0 means a permanent ban; otherwise a monotonic-ns deadline)

5. Accounting (only reached if the packet is going to PASS):
   ├─ global_stats_map[0].bytes   += frame_len ;  .packets += 1
   └─ stats_map[src].bytes        += frame_len ;  .packets += 1
      (creates the per-source entry on first sight)

6. XDP_PASS
```

Two subtleties:

- **Order matters — accounting comes after the blacklist check.** A packet that
  is dropped is *not* counted. So already-banned attack traffic does not inflate
  the global total and does not appear in the top-talker list. This makes smart
  mode **self-correcting**: once the worst offenders are banned, their traffic
  stops counting, the interface total falls back under the global threshold, the
  gate closes, and no further IPs are banned. See
  [the two ban rules](#the-two-ban-rules).
- **Whitelist comes before everything.** Whitelisted admin/SSH addresses are
  neither accounted nor bannable; they cannot lock you out and cannot be dropped
  by a stale blacklist entry.

`frame_len` is `data_end - data` — the on-wire frame size seen at ingress. That is
why the daemon's Mbps is close to, but not identical to, a provider's billing
figure.

## The loader

[`src/xdp_loader.c`](../src/xdp_loader.c) is a small libbpf program with two
subcommands. It is the only component that touches the XDP attachment itself.

**`load IFACE OBJ PIN_DIR [auto|native|generic]`**

1. Raise `RLIMIT_MEMLOCK` (BPF maps are locked memory).
2. `bpf_object__open_file` + `bpf_object__load` the compiled `.bpf.o`.
3. Find the program by name `xdp_rate_limiter`.
4. **Self-heal:** detach any leftover instance of *our own* program first, so an
   unclean previous stop doesn't make the attach fail with `EBUSY`. Foreign XDP
   programs are left alone unless `XDP_FORCE=1`.
5. Attach: in `auto` mode try **native** (driver) XDP first, fall back to
   **generic** (SKB) if the driver doesn't support it.
6. Wipe and recreate `PIN_DIR`, then pin all maps and the program into it. Wiping
   first makes restarts idempotent — stale pins from a prior run would otherwise
   make pinning fail with `EEXIST`.
7. Record the attach mode in a `mode` file inside the pin dir.

**`unload IFACE PIN_DIR [--force]`**

- Reads the pinned program's id and detaches it only if the id currently attached
  to the interface matches — so it removes *its own* program and never a foreign
  one. With `--force` (or `XDP_FORCE=1`) it detaches whatever is attached.
- If the pin is gone (crash, partial cleanup) it falls back to **name-based**
  detach so an orphaned copy of our own program is still removed.
- Finally `rm -rf` the pin dir.

The identity trick throughout is the **program name** `xdp_rate_limiter`
(`XDP_PROG_NAME`), which the kernel exposes in `bpf_prog_info.name`. That is how
the loader distinguishes "mine" from "someone else's" without a pin.

## Control plane: the daemon

[`src/xdp_rate_daemon.py`](../src/xdp_rate_daemon.py) talks to the pinned maps
directly through the `bpf(2)` syscall via `ctypes` — no BCC, no libbpf. The
`BpfMap` class wraps a pinned map (obtained with `BPF_OBJ_GET` on its path) and
offers `lookup` / `update` / `delete` / `keys` / `items`.

Startup (`XdpRateDaemon.__init__`):

1. Open the four pinned maps, declaring each one's key/value sizes and whether it
   is per-CPU (this must match the C structs exactly).
2. `reload_config(force=True)` — load `config.json` and push the whitelist into
   `whitelist_lpm_map`.
3. `load_existing_bans()` — read `blacklist_map`, drop already-expired entries,
   and remember the rest. This recovers bans after an *unclean* stop where the
   pinned maps survived (crash, `SIGKILL`); a clean stop/restart wipes the pins
   first (see [systemd wiring](#systemd-wiring)), so there is usually nothing to
   recover — the read simply returns an empty map.

Then `run()` loops: `tick()` every `interval_seconds`, catching and logging any
exception as `tick failed` (so a transient error never kills the daemon).

### One tick, step by step

```
tick():
  reload_config()                     # hot-reload if config.json mtime changed
  if first tick:                      # need a baseline before any delta exists
      seed prev counters ; return
  elapsed_s = (now - prev_tick) monotonic
  cleanup_expired_bans(now)           # remove & log UNBAN for lapsed bans
  global_mbps, global_pps = read_global_rate(elapsed_s)
  rates = read_rates(elapsed_s)       # per-IP deltas → Mbps/PPS, sorted desc
  candidates = {}
  for r in rates:                     # RULE 1 — direct per-IP (always on)
      if r over per_ip_*_limit: candidates[r] = "direct-per-ip"
  if smart_global_enabled and (global over global_*_limit):   # RULE 2 — smart
      for r in rates:
          if r over smart_ban_min_*: candidates.setdefault(r, "smart-global")
  for r in candidates sorted by rate desc, up to max_bans_per_tick:
      ban(r)
  every summary_log_interval_seconds: log one summary line
```

A metric threshold of `0` means **disabled**: the helper `over(value, limit)`
returns true only when `limit > 0 and value >= limit`. So `global_pps_limit: 0`
means "use only Mbps for the global gate". You can set both Mbps and PPS limits;
either one crossing is enough.

## The two ban rules

Both rules build candidates from the same per-IP rate list; a source can be flagged
by either.

**Rule 1 — direct per-IP limit** (`per_ip_mbps_limit` / `per_ip_pps_limit`).
Unconditional: any single IP over the limit is banned immediately, regardless of
how busy the interface is. Off by default (limits `0`). Reason logged:
`direct-per-ip`.

**Rule 2 — smart global mode** (`smart_global_enabled` + the `global_*` and
`smart_ban_min_*` pairs). A two-gate rule that bans an IP only if **both** are
true this tick:

1. *Global gate* — the whole interface is above `global_mbps_limit` (or
   `global_pps_limit`). If not, no smart bans at all this tick.
2. *Per-source gate* — the individual IP is above `smart_ban_min_mbps` (or
   `smart_ban_min_pps`).

Reason logged: `smart-global`. The point is to leave even fairly heavy clients
alone while the link is calm, and only start banning the biggest contributors once
the aggregate actually becomes a problem. Combined with the
[accounting-after-blacklist order](#data-plane-the-xdp-program), the system tends
to ban just enough IPs to bring the total back under the gate, then stop.

Candidates from both rules are merged (direct-per-ip wins the reason if an IP hits
both, because it is added first), sorted by rate, and banned highest-first up to
`max_bans_per_tick` — a safety cap so a measurement glitch can't ban thousands of
IPs in one tick.

## Ban lifecycle

- **Issuing** (`ban()`): skip if whitelisted; compute `expires_ns = now +
  ban_seconds` (or `0` for a permanent ban when `ban_seconds == 0`); write the
  entry into `blacklist_map`. From the next packet on, the XDP program drops that
  source.
- **Extending**: if the IP is already banned and still offending, the ban is
  pushed out to the new, later expiry when `extend_ban_on_repeat` is true;
  otherwise the existing ban is left to run out. A ban is never shortened.
- **Expiring**: bans carry an absolute monotonic-ns deadline. The XDP program
  stops dropping once `now >= expires_ns`; the daemon's `cleanup_expired_bans`
  deletes the map entry and logs `UNBAN`. Both sides use the **same monotonic
  clock** (`bpf_ktime_get_ns()` in the kernel, `time.monotonic_ns()` in Python),
  which is why the deadlines line up.
- **Map full**: `blacklist_map` holds 262144 entries. On overflow `update`
  fails with `E2BIG`; the daemon logs an error and skips the ban (existing bans
  keep working).
- **Dry-run** (`dry_run: true`): everything runs and logs `DRY-RUN BAN`, but no
  entry is written — nothing is actually dropped. Use it to calibrate thresholds
  against real traffic.

## Reading counters correctly

Three details make the userspace read match the kernel's layout:

- **Per-CPU summing.** A per-CPU map lookup returns one value block *per possible
  CPU* (from `/sys/devices/system/cpu/possible`, not just online CPUs), each
  padded up to 8 bytes. `unpack_stats` walks the blocks and sums them; for a
  regular map it simply loops once.
- **Deltas, not absolutes.** Counters only ever grow. Each tick the daemon
  subtracts the previous sample and divides by the measured `elapsed_s` to get a
  rate: `Mbps = dbytes*8 / 1e6 / elapsed_s`, `PPS = dpackets / elapsed_s`. New
  entries (no previous sample) are skipped for one tick, which is why a brand-new
  source is only caught on its second appearance.
- **Batch iteration.** Scanning the per-source table naively costs two syscalls
  per entry (`GET_NEXT_KEY` + `LOOKUP_ELEM`). With tens of thousands of live
  sources that dominates CPU, so `BpfMap.items` uses `BPF_MAP_LOOKUP_BATCH` to
  pull up to ~1024 key+value pairs per syscall, and falls back permanently to the
  per-key path on kernels without batch support (pre-5.6, `EINVAL`/`ENOTSUPP`).

## Cross-component contracts

Because the C program, the C loader, and the Python daemon are three separate
binaries sharing pinned maps *by raw memory layout*, some things must move in
lockstep. Change one side without the other and you get silent corruption, not a
compile error.

- **Map key/value sizes** are hardcoded in the daemon (`BpfMap(path, key_size,
  value_size, percpu=...)`). If you change a struct in the `.bpf.c` file, update
  the matching `BpfMap` sizes and every `struct.pack` / `unpack` format string.
- **Byte order.** IPv4 keys are stored in *network* order (`inet_aton`).
  `ipv4_lpm_key` is *little-endian* `prefixlen` followed by the network-order
  address. Counters and `expires_ns` are little-endian `u64`.
- **Program name** `xdp_rate_limiter` is the loader's identity check. Renaming the
  `SEC("xdp")` function breaks self-healing detach unless `xdp_loader.c` is updated
  too.
- **`bpf(2)` command numbers** in the daemon are raw syscall constants
  (`BPF_OBJ_GET = 7`, `BPF_MAP_LOOKUP_BATCH = 24`, …). They are not interchangeable
  with the info-by-fd command; don't "correct" them.

## systemd wiring

The template unit
[`systemd/xdp-rate-limit@.service`](../systemd/xdp-rate-limit@.service) ties one
service instance to one interface via the `%i` specifier
(`xdp-rate-limit@ens3` → interface `ens3`). It runs the glue script
[`src/xdp-rate-limit-wrapper`](../src/xdp-rate-limit-wrapper):

- `ExecStart … %i start` — ensure bpffs is mounted, run the loader `load`, then
  `exec` the daemon (so the daemon becomes the service's main process and receives
  `SIGTERM` on stop).
- `ExecStopPost … %i stop` — run the loader `unload` to detach XDP and remove the
  pins after the daemon exits.

`Restart=on-failure` brings the daemon back after a crash; because `load` is
idempotent and self-healing, a restart cleanly re-attaches rather than piling up
duplicate XDP programs. A steadily climbing `NRestarts` is the signal to
investigate a genuine restart loop.

Note what a restart does to bans. On a **clean** stop/restart `ExecStopPost` runs
`unload`, which removes the pin directory and with it `blacklist_map`; `ExecStart`
then recreates the maps empty, so the active bans are cleared. This is intended and
harmless — bans are temporary, and any source still over the limit is re-banned
within a tick or two. `load_existing_bans()` only recovers bans after an **unclean**
stop where `ExecStopPost` did not run and the pins survived (crash, `SIGKILL`).
Either way `/sys/fs/bpf` is a tmpfs, so no bans survive a reboot.
