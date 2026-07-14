#!/usr/bin/env python3
"""
Smart XDP rate-limit daemon.

Reads pinned BPF maps produced by xdp_rate_limit.bpf.c and bans noisy IPv4
source addresses. It supports two independent rules:

1) Direct per-IP limit: ban a source immediately if it exceeds per_ip_mbps_limit
   or per_ip_pps_limit.
2) Smart global mode: only when total ingress traffic on the interface exceeds
   global_mbps_limit/global_pps_limit, ban sources whose own traffic exceeds
   smart_ban_min_mbps/smart_ban_min_pps.

No BCC dependency. Uses the bpf() syscall directly through ctypes.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import ipaddress
import json
import logging
import os
import platform
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# bpf(2) commands
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_OBJ_GET = 7  # NOTE: 7 is BPF_OBJ_GET; 15 is BPF_OBJ_GET_INFO_BY_FD (do not confuse)
BPF_MAP_LOOKUP_BATCH = 24  # bulk key+value dump; kernel >= 5.6. Falls back if absent.

BPF_ANY = 0

LOG = logging.getLogger("xdp-rate-limit")


def _sys_bpf_nr() -> int:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return 321
    if machine in ("aarch64", "arm64"):
        return 280
    if machine in ("armv7l", "armv8l", "arm"):
        return 386
    if machine in ("ppc64le",):
        return 361
    if machine in ("s390x",):
        return 351
    raise RuntimeError(f"Unsupported architecture for direct bpf syscall: {machine}")


SYS_BPF = _sys_bpf_nr()
LIBC = ctypes.CDLL(None, use_errno=True)


def _round_up8(n: int) -> int:
    return (n + 7) & ~7


def _num_possible_cpus() -> int:
    """Number of possible CPUs, matching the kernel's per-CPU map layout.

    Per-CPU BPF maps always allocate one slot per *possible* CPU (not just
    online ones), so we must read the same count the kernel uses.
    """
    try:
        spec = Path("/sys/devices/system/cpu/possible").read_text().strip()
    except OSError:
        return os.cpu_count() or 1
    total = 0
    for part in spec.split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            total += int(b) - int(a) + 1
        else:
            total += 1
    return max(1, total)


NUM_POSSIBLE_CPUS = _num_possible_cpus()


class BpfAttrMapElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class BpfAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class BpfAttrBatch(ctypes.Structure):
    # Matches the BPF_MAP_*_BATCH slice of union bpf_attr (56 bytes, no padding).
    _fields_ = [
        ("in_batch", ctypes.c_uint64),   # cursor in; 0 to start from the beginning
        ("out_batch", ctypes.c_uint64),  # cursor out; feed back as in_batch next call
        ("keys", ctypes.c_uint64),
        ("values", ctypes.c_uint64),
        ("count", ctypes.c_uint32),      # in: buffer capacity; out: entries filled
        ("map_fd", ctypes.c_uint32),
        ("elem_flags", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


def _bpf(cmd: int, attr: ctypes.Structure) -> int:
    ret = LIBC.syscall(SYS_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return int(ret)


def _bpf_raw(cmd: int, attr: ctypes.Structure) -> Tuple[int, int]:
    """Like _bpf but returns (ret, errno) instead of raising.

    Needed for BPF_MAP_LOOKUP_BATCH, where the final batch reports ENOENT *and*
    still fills attr.count valid entries — so the caller must read attr.count
    even on the "error" that signals end-of-map.
    """
    ret = LIBC.syscall(SYS_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        return int(ret), ctypes.get_errno()
    return int(ret), 0


def _ptr(buf: ctypes.Array) -> int:
    return ctypes.addressof(buf)


class BpfMap:
    def __init__(self, path: Path, key_size: int, value_size: int, percpu: bool = False):
        self.path = Path(path)
        self.key_size = key_size
        self.value_size = value_size
        self.percpu = percpu
        # Per-CPU maps return one value per possible CPU, each padded to 8 bytes.
        self.value_stride = _round_up8(value_size) if percpu else value_size
        self.buf_size = self.value_stride * (NUM_POSSIBLE_CPUS if percpu else 1)
        self.fd = self.obj_get(self.path)
        # Optimistically use BPF_MAP_LOOKUP_BATCH; flipped off on the first call
        # if the running kernel doesn't support it (pre-5.6).
        self._use_batch = True

    @staticmethod
    def obj_get(path: Path) -> int:
        b = os.fsencode(str(path)) + b"\0"
        buf = ctypes.create_string_buffer(b)
        attr = BpfAttrObjGet(_ptr(buf), 0, 0)
        return _bpf(BPF_OBJ_GET, attr)

    def lookup(self, key: bytes) -> Optional[bytes]:
        if len(key) != self.key_size:
            raise ValueError(f"bad key size for {self.path}: {len(key)} != {self.key_size}")
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        vbuf = ctypes.create_string_buffer(self.buf_size)
        attr = BpfAttrMapElem(self.fd, _ptr(kbuf), _ptr(vbuf), 0)
        try:
            _bpf(BPF_MAP_LOOKUP_ELEM, attr)
            return bytes(vbuf.raw)
        except OSError as e:
            if e.errno == errno.ENOENT:
                return None
            raise

    def update(self, key: bytes, value: bytes, flags: int = BPF_ANY) -> None:
        if len(key) != self.key_size:
            raise ValueError(f"bad key size for {self.path}: {len(key)} != {self.key_size}")
        if len(value) != self.value_size:
            raise ValueError(f"bad value size for {self.path}: {len(value)} != {self.value_size}")
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        vbuf = ctypes.create_string_buffer(value, self.value_size)
        attr = BpfAttrMapElem(self.fd, _ptr(kbuf), _ptr(vbuf), flags)
        _bpf(BPF_MAP_UPDATE_ELEM, attr)

    def delete(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(f"bad key size for {self.path}: {len(key)} != {self.key_size}")
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        attr = BpfAttrMapElem(self.fd, _ptr(kbuf), 0, 0)
        try:
            _bpf(BPF_MAP_DELETE_ELEM, attr)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

    def keys(self, max_keys: int = 0) -> Iterator[bytes]:
        prev: Optional[bytes] = None
        count = 0
        while True:
            nbuf = ctypes.create_string_buffer(self.key_size)
            if prev is None:
                attr = BpfAttrMapElem(self.fd, 0, _ptr(nbuf), 0)
            else:
                kbuf = ctypes.create_string_buffer(prev, self.key_size)
                attr = BpfAttrMapElem(self.fd, _ptr(kbuf), _ptr(nbuf), 0)
            try:
                _bpf(BPF_MAP_GET_NEXT_KEY, attr)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    break
                raise
            key = bytes(nbuf.raw)
            yield key
            prev = key
            count += 1
            if max_keys and count >= max_keys:
                break

    def items(self, max_keys: int = 0) -> Iterator[Tuple[bytes, bytes]]:
        # One BPF_MAP_LOOKUP_BATCH call returns up to `batch_size` key+value pairs,
        # versus two syscalls (GET_NEXT_KEY + LOOKUP_ELEM) per entry the naive way.
        # On a busy stats_map (tens of thousands of source IPs) this is the
        # difference between a handful of syscalls per tick and ~100k of them.
        if self._use_batch:
            try:
                yield from self._items_batch(max_keys=max_keys)
                return
            except OSError as e:
                # EINVAL/ENOTSUPP => kernel lacks batch ops; degrade permanently.
                if e.errno in (errno.EINVAL, errno.ENOTSUPP, errno.EOPNOTSUPP):
                    LOG.warning(
                        "BPF_MAP_LOOKUP_BATCH unavailable for %s (%s); "
                        "falling back to per-key iteration",
                        self.path, os.strerror(e.errno),
                    )
                    self._use_batch = False
                else:
                    raise
        for key in self.keys(max_keys=max_keys):
            val = self.lookup(key)
            if val is not None:
                yield key, val

    def _items_batch(self, max_keys: int = 0, batch_size: int = 1024) -> List[Tuple[bytes, bytes]]:
        # Collect into a list rather than yielding lazily: if the very first call
        # fails as unsupported we must be able to fall back without having emitted
        # a partial (duplicated) result. read_rates materializes everything anyway.
        out: List[Tuple[bytes, bytes]] = []
        keys_buf = ctypes.create_string_buffer(self.key_size * batch_size)
        vals_buf = ctypes.create_string_buffer(self.buf_size * batch_size)
        out_batch = ctypes.create_string_buffer(self.key_size)
        in_batch: Optional[ctypes.Array] = None

        while True:
            attr = BpfAttrBatch()
            attr.in_batch = _ptr(in_batch) if in_batch is not None else 0
            attr.out_batch = _ptr(out_batch)
            attr.keys = _ptr(keys_buf)
            attr.values = _ptr(vals_buf)
            attr.count = batch_size
            attr.map_fd = self.fd
            attr.elem_flags = 0
            attr.flags = 0

            ret, err = _bpf_raw(BPF_MAP_LOOKUP_BATCH, attr)
            n = attr.count  # entries actually filled — valid even when ret < 0

            for i in range(n):
                k = bytes(keys_buf.raw[i * self.key_size:(i + 1) * self.key_size])
                v = bytes(vals_buf.raw[i * self.buf_size:(i + 1) * self.buf_size])
                out.append((k, v))
                if max_keys and len(out) >= max_keys:
                    return out

            if ret < 0:
                if err == errno.ENOENT:
                    return out  # map exhausted; entries above were the last batch
                raise OSError(err, os.strerror(err))
            if n == 0:
                return out  # no progress and no error: nothing left to read

            # Advance the cursor: this batch's out_batch becomes next in_batch.
            in_batch = ctypes.create_string_buffer(bytes(out_batch.raw), self.key_size)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


@dataclass
class Rate:
    key: bytes
    ip: str
    mbps: float
    pps: float
    bytes_delta: int
    packets_delta: int


@dataclass
class Config:
    interval_seconds: float = 1.0

    # Direct per-IP limits. 0 disables the corresponding check.
    per_ip_mbps_limit: float = 0.0
    per_ip_pps_limit: float = 0.0

    # Smart mode: first require the whole interface to cross a global threshold.
    smart_global_enabled: bool = True
    global_mbps_limit: float = 10.0
    global_pps_limit: float = 0.0

    # Then ban only IPs above these per-source thresholds.
    smart_ban_min_mbps: float = 3.0
    smart_ban_min_pps: float = 0.0

    ban_seconds: int = 300
    extend_ban_on_repeat: bool = True
    max_bans_per_tick: int = 50
    max_scan_entries: int = 262144
    log_top_n: int = 10
    summary_log_interval_seconds: int = 10
    # Slow mode: while the limiter is idle (nothing banned, global gate not crossed)
    # the summary is logged this rarely instead. 0 disables it — always use
    # summary_log_interval_seconds. Ignored under dry_run.
    idle_summary_log_interval_seconds: int = 300
    whitelist: Tuple[str, ...] = ("127.0.0.1",)
    dry_run: bool = False

    @staticmethod
    def from_json(path: Path) -> "Config":
        data = json.loads(path.read_text(encoding="utf-8"))
        c = Config()
        for k, v in data.items():
            if not hasattr(c, k):
                LOG.warning("Unknown config key ignored: %s", k)
                continue
            if k == "whitelist":
                v = tuple(v)
            setattr(c, k, v)
        if c.interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        if c.ban_seconds < 0:
            raise ValueError("ban_seconds must be >= 0")
        if c.max_bans_per_tick < 1:
            raise ValueError("max_bans_per_tick must be >= 1")
        if c.summary_log_interval_seconds < 0:
            raise ValueError("summary_log_interval_seconds must be >= 0")
        if c.idle_summary_log_interval_seconds < 0:
            raise ValueError("idle_summary_log_interval_seconds must be >= 0")
        return c


class XdpRateDaemon:
    def __init__(self, iface: str, config_path: Path, pin_dir: Path):
        self.iface = iface
        self.config_path = config_path
        self.pin_dir = pin_dir
        self.config_mtime = 0.0
        self.config = Config()
        self.stop = False

        self.stats = BpfMap(pin_dir / "stats_map", 4, 16, percpu=True)
        self.global_stats = BpfMap(pin_dir / "global_stats_map", 4, 16, percpu=True)
        self.blacklist = BpfMap(pin_dir / "blacklist_map", 4, 8)
        self.whitelist_lpm = BpfMap(pin_dir / "whitelist_lpm_map", 8, 1)

        self.prev_ip: Dict[bytes, Tuple[int, int]] = {}
        self.prev_global: Optional[Tuple[int, int]] = None
        self.prev_tick_ns: Optional[int] = None
        self.known_bans: Dict[bytes, int] = {}
        self.last_summary_ns = 0
        self.reload_config(force=True)
        self.load_existing_bans()

    @staticmethod
    def ip_key(ip: str) -> bytes:
        return socket.inet_aton(ip)

    @staticmethod
    def key_to_ip(key: bytes) -> str:
        return socket.inet_ntoa(key)

    @staticmethod
    def unpack_stats(raw: bytes) -> Tuple[int, int]:
        # traffic_stats is two u64 (16 bytes, already 8-aligned). For per-CPU
        # maps `raw` holds one 16-byte block per CPU; sum them. For regular
        # maps there is a single block, so this loops exactly once.
        total_bytes = 0
        total_packets = 0
        for off in range(0, len(raw), 16):
            b, p = struct.unpack_from("<QQ", raw, off)
            total_bytes += b
            total_packets += p
        return total_bytes, total_packets

    def reload_config(self, force: bool = False) -> None:
        st = self.config_path.stat()
        if not force and st.st_mtime == self.config_mtime:
            return
        self.config = Config.from_json(self.config_path)
        self.config_mtime = st.st_mtime
        self.sync_whitelist()
        idle_every = self.config.idle_summary_log_interval_seconds
        if self.config.dry_run:
            idle_desc = "off, dry-run"
        elif idle_every > 0:
            idle_desc = f"{idle_every}s"
        else:
            idle_desc = "off"
        LOG.info(
            "Config loaded: interval %.2fs, smart=%s, global %.3f Mbps / %.0f pps, smart IP >= %.3f Mbps / %.0f pps, direct IP %.3f Mbps / %.0f pps, ban %ss, summary %ss (idle %s)",
            self.config.interval_seconds,
            "on" if self.config.smart_global_enabled else "off",
            self.config.global_mbps_limit,
            self.config.global_pps_limit,
            self.config.smart_ban_min_mbps,
            self.config.smart_ban_min_pps,
            self.config.per_ip_mbps_limit,
            self.config.per_ip_pps_limit,
            self.config.ban_seconds,
            self.config.summary_log_interval_seconds,
            idle_desc,
        )

    @staticmethod
    def whitelist_key(entry: str) -> bytes:
        net = ipaddress.ip_network(entry, strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 whitelist is not supported by this XDP program: {entry}")
        # struct ipv4_lpm_key: little-endian prefixlen + network-order IPv4 address
        return struct.pack("<I", int(net.prefixlen)) + socket.inet_aton(str(net.network_address))

    def sync_whitelist(self) -> None:
        desired = set()
        for entry in self.config.whitelist:
            try:
                desired.add(self.whitelist_key(entry))
            except Exception as e:
                LOG.warning("Skipping invalid whitelist entry %r: %s", entry, e)

        existing = set(self.whitelist_lpm.keys(max_keys=100000))
        for key in desired - existing:
            self.whitelist_lpm.update(key, b"\x01")
        for key in existing - desired:
            self.whitelist_lpm.delete(key)
        if desired:
            LOG.info("Whitelist synced: %d IPv4 entries/CIDRs", len(desired))

    def load_existing_bans(self) -> None:
        now_ns = time.monotonic_ns()
        for key, raw in self.blacklist.items(max_keys=self.config.max_scan_entries):
            (expires_ns,) = struct.unpack("<Q", raw)
            if expires_ns and expires_ns <= now_ns:
                self.blacklist.delete(key)
            else:
                self.known_bans[key] = expires_ns
        if self.known_bans:
            LOG.info("Loaded %d active bans from blacklist map", len(self.known_bans))

    def cleanup_expired_bans(self, now_ns: int) -> None:
        expired = [key for key, exp in self.known_bans.items() if exp and exp <= now_ns]
        for key in expired:
            self.blacklist.delete(key)
            self.known_bans.pop(key, None)
            LOG.info("UNBAN %s", self.key_to_ip(key))

    def is_whitelisted_ip_key(self, key: bytes) -> bool:
        ip = ipaddress.ip_address(self.key_to_ip(key))
        for entry in self.config.whitelist:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if ip in net:
                return True
        return False

    def ban(self, rate: Rate, reason: str, now_ns: int) -> bool:
        if self.is_whitelisted_ip_key(rate.key):
            return False

        expires_ns = 0 if self.config.ban_seconds == 0 else now_ns + self.config.ban_seconds * 1_000_000_000
        old_exp = self.known_bans.get(rate.key)
        if old_exp and old_exp > now_ns and not self.config.extend_ban_on_repeat:
            return False
        if old_exp and old_exp >= expires_ns:
            return False

        if not self.config.dry_run:
            try:
                self.blacklist.update(rate.key, struct.pack("<Q", expires_ns))
            except OSError as e:
                if e.errno == errno.E2BIG:
                    LOG.error(
                        "blacklist_map is full (%d entries); cannot ban %s. "
                        "Increase max_entries in the BPF program or lower ban_seconds.",
                        len(self.known_bans),
                        rate.ip,
                    )
                    return False
                raise
        self.known_bans[rate.key] = expires_ns

        until = "permanent" if expires_ns == 0 else f"{self.config.ban_seconds}s"
        prefix = "DRY-RUN BAN" if self.config.dry_run else "BAN"
        LOG.warning(
            "%s %s for %s: %.3f Mbps, %.0f pps, reason=%s",
            prefix,
            rate.ip,
            until,
            rate.mbps,
            rate.pps,
            reason,
        )
        return True

    def read_rates(self, elapsed_s: float) -> List[Rate]:
        current: Dict[bytes, Tuple[int, int]] = {}
        rates: List[Rate] = []
        for key, raw in self.stats.items(max_keys=self.config.max_scan_entries):
            bytes_total, packets_total = self.unpack_stats(raw)
            current[key] = (bytes_total, packets_total)
            prev = self.prev_ip.get(key)
            if prev is None:
                continue
            dbytes = max(0, bytes_total - prev[0])
            dpkts = max(0, packets_total - prev[1])
            if dbytes == 0 and dpkts == 0:
                continue
            mbps = (dbytes * 8.0) / 1_000_000.0 / elapsed_s
            pps = dpkts / elapsed_s
            rates.append(Rate(key=key, ip=self.key_to_ip(key), mbps=mbps, pps=pps, bytes_delta=dbytes, packets_delta=dpkts))
        self.prev_ip = current
        rates.sort(key=lambda r: (r.mbps, r.pps), reverse=True)
        return rates

    def read_global_rate(self, elapsed_s: float) -> Tuple[float, float]:
        raw = self.global_stats.lookup(struct.pack("<I", 0))
        if raw is None:
            return 0.0, 0.0
        bytes_total, packets_total = self.unpack_stats(raw)
        if self.prev_global is None:
            self.prev_global = (bytes_total, packets_total)
            return 0.0, 0.0
        dbytes = max(0, bytes_total - self.prev_global[0])
        dpkts = max(0, packets_total - self.prev_global[1])
        self.prev_global = (bytes_total, packets_total)
        return (dbytes * 8.0) / 1_000_000.0 / elapsed_s, dpkts / elapsed_s

    @staticmethod
    def over(value: float, limit: float) -> bool:
        return limit > 0 and value >= limit

    def rate_hits_direct_limit(self, r: Rate) -> bool:
        return self.over(r.mbps, self.config.per_ip_mbps_limit) or self.over(r.pps, self.config.per_ip_pps_limit)

    def rate_hits_smart_minimum(self, r: Rate) -> bool:
        return self.over(r.mbps, self.config.smart_ban_min_mbps) or self.over(r.pps, self.config.smart_ban_min_pps)

    def tick(self) -> None:
        self.reload_config(force=False)
        now_ns = time.monotonic_ns()
        if self.prev_tick_ns is None:
            self.prev_tick_ns = now_ns
            self.read_global_rate(1.0)
            self.read_rates(1.0)
            return

        elapsed_s = max(0.001, (now_ns - self.prev_tick_ns) / 1_000_000_000.0)
        self.prev_tick_ns = now_ns

        self.cleanup_expired_bans(now_ns)

        global_mbps, global_pps = self.read_global_rate(elapsed_s)
        rates = self.read_rates(elapsed_s)

        candidates: Dict[bytes, Tuple[Rate, str]] = {}

        for r in rates:
            if self.rate_hits_direct_limit(r):
                candidates[r.key] = (r, "direct-per-ip")

        global_exceeded = False
        if self.config.smart_global_enabled:
            global_exceeded = self.over(global_mbps, self.config.global_mbps_limit) or self.over(global_pps, self.config.global_pps_limit)
            if global_exceeded:
                for r in rates:
                    if self.rate_hits_smart_minimum(r):
                        candidates.setdefault(r.key, (r, "smart-global"))

        ordered = sorted(candidates.values(), key=lambda x: (x[0].mbps, x[0].pps), reverse=True)
        bans_done = 0
        for r, reason in ordered:
            if bans_done >= self.config.max_bans_per_tick:
                break
            if self.ban(r, reason, now_ns):
                bans_done += 1

        # Idle = the limiter has nothing to do: nobody banned, nobody worth banning,
        # global gate not crossed. The moment any of that changes we fall back to the
        # normal interval, and since the last summary is then long overdue, the first
        # tick of an event logs immediately.
        # dry_run opts out: it exists to watch the numbers while picking thresholds,
        # and until those are set the limiter is idle by definition.
        idle = not global_exceeded and not candidates and not self.known_bans
        slow_mode = self.config.idle_summary_log_interval_seconds > 0 and not self.config.dry_run
        summary_interval = self.config.summary_log_interval_seconds
        if idle and slow_mode:
            summary_interval = self.config.idle_summary_log_interval_seconds

        if now_ns - self.last_summary_ns >= summary_interval * 1_000_000_000:
            self.last_summary_ns = now_ns
            top = ", ".join(f"{r.ip}={r.mbps:.2f}Mbps/{r.pps:.0f}pps" for r in rates[: self.config.log_top_n])
            # The iface is in the syslog identifier (xdp-rate-limit@<iface>), not repeated here.
            LOG.info(
                "global=%.3fMbps/%.0fpps smart_exceeded=%s active_bans=%d top=[%s]",
                global_mbps,
                global_pps,
                global_exceeded,
                len(self.known_bans),
                top,
            )

    def run(self) -> None:
        LOG.info("Daemon started for iface=%s pin_dir=%s", self.iface, self.pin_dir)
        while not self.stop:
            try:
                self.tick()
            except Exception:
                LOG.exception("tick failed")
            time.sleep(self.config.interval_seconds)
        LOG.info("Daemon stopped")

    def request_stop(self, *_args: object) -> None:
        self.stop = True


def under_journald() -> bool:
    # systemd sets JOURNAL_STREAM to "<dev>:<ino>" of the stream it handed us;
    # it only means "journald owns our log" if stderr is that same stream.
    spec = os.environ.get("JOURNAL_STREAM")
    if not spec:
        return False
    try:
        dev, ino = spec.split(":", 1)
        st = os.fstat(sys.stderr.fileno())
        return st.st_dev == int(dev) and st.st_ino == int(ino)
    except (ValueError, OSError):
        return False


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    # journald timestamps every line itself, so asctime would print the time twice.
    fmt = "%(levelname)s %(message)s" if under_journald() else "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(level=level, format=fmt)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Smart XDP rate-limit daemon")
    p.add_argument("iface", help="network interface name, e.g. eth0")
    p.add_argument("--config", default="/etc/xdp-rate-limit/config.json", help="path to config.json")
    p.add_argument("--pin-dir", default=None, help="BPF pin dir; default /sys/fs/bpf/xdp-rate-limit/<iface>")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)

    if os.geteuid() != 0:
        print("This daemon must run as root.", file=sys.stderr)
        return 1

    pin_dir = Path(args.pin_dir) if args.pin_dir else Path("/sys/fs/bpf/xdp-rate-limit") / args.iface
    daemon = XdpRateDaemon(args.iface, Path(args.config), pin_dir)
    signal.signal(signal.SIGTERM, daemon.request_stop)
    signal.signal(signal.SIGINT, daemon.request_stop)
    daemon.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
