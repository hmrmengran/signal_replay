#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Union
import struct, zlib
import threading

import ctypes

from discover_live_lidar import discovery_live_lidar_interface
from discover_fake_lidar import discovery_fake_lidar_interface


class InnoCommonHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        # 6 bytes
        ("version", ctypes.c_uint8 * 6),
        # 4 bytes
        ("checksum", ctypes.c_uint32),
        # 4 bytes
        ("size", ctypes.c_uint32),
        # 2 bytes (packed)
        ("source_id", ctypes.c_uint8, 4),
        ("timestamp_sync_type", ctypes.c_uint8, 4),
        ("lidar_type", ctypes.c_uint8),
        # 8 bytes
        ("ts_start_us", ctypes.c_double),
        # 2 bytes
        ("lidar_mode", ctypes.c_uint8),
        ("lidar_status", ctypes.c_uint8),
    ]


class InnoDataPacket(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("common", InnoCommonHeader),
        
        ("idx", ctypes.c_uint64),
        ("sub_idx", ctypes.c_uint16),
        ("sub_seq", ctypes.c_uint16),
 
        ("type", ctypes.c_uint32, 8),
        ("item_number", ctypes.c_uint32, 24),
        ("item_size", ctypes.c_uint16),
        ("topic", ctypes.c_uint32),
 
        ("scanner_direction", ctypes.c_uint16, 1),
        ("use_reflectance", ctypes.c_uint16, 1),
        ("multi_return_mode", ctypes.c_uint16, 3),
        ("confidence_level", ctypes.c_uint16, 2),
        ("is_last_sub_frame", ctypes.c_uint16, 1),
        ("is_last_sequence", ctypes.c_uint16, 1),
        ("has_tail", ctypes.c_uint16, 1),
        ("frame_sync_locked", ctypes.c_uint16, 1),
        ("is_first_sub_frame", ctypes.c_uint16, 1),
        ("last_four_channel", ctypes.c_uint16, 1),
        ("long_distance_mode", ctypes.c_uint16, 1),
        ("reserved_flag", ctypes.c_uint16, 2),
 
        ("roi_h_angle", ctypes.c_int16),
        ("roi_v_angle", ctypes.c_int16),
 
        ("extend_reserved", ctypes.c_uint32 * 4)
    ]
 
class InnoDataPacketV1(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("common", InnoCommonHeader),
        
        ("idx", ctypes.c_uint64),
        ("sub_idx", ctypes.c_uint16),
        ("sub_seq", ctypes.c_uint16),
 
        ("type", ctypes.c_uint32, 8),
        ("item_number", ctypes.c_uint32, 24),
        ("item_size", ctypes.c_uint16),
        ("topic", ctypes.c_uint32),
 
        ("scanner_direction", ctypes.c_uint16, 1),
        ("use_reflectance", ctypes.c_uint16, 1),
        ("multi_return_mode", ctypes.c_uint16, 3),
        ("confidence_level", ctypes.c_uint16, 2),
        ("is_last_sub_frame", ctypes.c_uint16, 1),
        ("is_last_sequence", ctypes.c_uint16, 1),
        ("has_tail", ctypes.c_uint16, 1),
        ("frame_sync_locked", ctypes.c_uint16, 1),
        ("is_first_sub_frame", ctypes.c_uint16, 1),
        ("last_four_channel", ctypes.c_uint16, 1),
        ("long_distance_mode", ctypes.c_uint16, 1),
        ("reserved_flag", ctypes.c_uint16, 2)
    ]

try:
    import requests
except Exception as e:
    raise SystemExit("This script requires the 'requests' package: pip install requests")

try:
    from scapy.all import AsyncSniffer, UDP, raw
    import queue
    import threading
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # We'll check this later when L2 capture is requested

# Default tolerance for LiDAR/NDJSON matching (milliseconds)
DEFAULT_LIDAR_MATCH_TOLERANCE_MS = 50


# -------------------- Data classes --------------------

@dataclass
class PhaseState:
    phase: int
    veh: str
    ped: str

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PhaseState":
        # Allow either {"phase":1,"state":{"veh":"G","ped":"NA"}} or {"phase":1,"veh":"G","ped":"NA"}
        phase = d.get("phase")
        if phase is None:
            raise ValueError("Missing 'phase' in phase entry")

        state = d.get("state", d)
        veh = state.get("veh")
        ped = state.get("ped")
        if veh is None or ped is None:
            raise ValueError("Missing 'veh' or 'ped' in phase entry/state")
        return PhaseState(phase=int(phase), veh=str(veh), ped=str(ped))

    def to_api_obj(self) -> Dict[str, Any]:
        return {"phase": self.phase, "state": {"veh": self.veh, "ped": self.ped}}


@dataclass
class Snapshot:
    ts_ms: int
    type: str
    phases: List[PhaseState]

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Snapshot":
        ts_ms = d.get("ts_ms")
        if ts_ms is None:
            raise ValueError("Missing 'ts_ms'")

        typ = d.get("type", "phase")
        if typ != "phase":
            raise ValueError(f"Unsupported 'type': {typ!r} (only 'phase' supported)")

        # Support "phases" or "data" as the array key
        arr = d.get("phases", d.get("data"))
        if arr is None or not isinstance(arr, list):
            raise ValueError("Missing 'phases' or 'data' array")

        phases = [PhaseState.from_dict(x) for x in arr]
        return Snapshot(ts_ms=int(ts_ms), type=str(typ), phases=phases)

    def to_api_body(self) -> Dict[str, Any]:
        return {"type": self.type, "ts_ms": self.ts_ms, "data": [p.to_api_obj() for p in self.phases]}


# -------------------- NDJSON Reader --------------------

def iter_ndjson(path: str) -> Iterable[Snapshot]:
    with open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, start=1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
                snap = Snapshot.from_dict(obj)
                yield snap
            except Exception as e:
                logging.error("NDJSON parse error at line %d: %s", ln, e)
                continue


# -------------------- REST Client --------------------

import json
from typing import Any, Dict

VEH_OK = {"G", "Y", "R"}
PED_OK = {"NA", "WALK", "DONT_WALK"}

def _validate_body_locally(body: Dict[str, Any]) -> None:
    if not isinstance(body.get("ts_ms"), int):
        raise ValueError("ts_ms must be int (ms)")
    if body.get("type") != "phase":
        raise ValueError('type must be "phase"')
    data = body.get("data")
    if not isinstance(data, list) or not data:
        raise ValueError("data must be a non-empty list")
    for i, p in enumerate(data):
        if not isinstance(p, dict):
            raise ValueError(f"phase[{i}] must be object")
        if "phase" not in p or "state" not in p:
            raise ValueError(f"phase[{i}] missing keys (phase/state)")
        st = p["state"]
        if not isinstance(st, dict):
            raise ValueError(f"phase[{i}].state must be object")
        veh, ped = st.get("veh"), st.get("ped")
        if veh not in VEH_OK:
            raise ValueError(f"phase[{i}].state.veh invalid: {veh}")
        if ped not in PED_OK:
            raise ValueError(f"phase[{i}].state.ped invalid: {ped}")

class SDLCClient:
    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def post_snapshot(self, snap: Snapshot) -> None:
        url = f"{self.base_url}/api/v1/signals/snapshot"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        body = snap.to_api_body()
        _validate_body_locally(body)
        resp = requests.post(url, headers=headers, json=body, timeout=self.timeout)

        if resp.status_code == 200:
            return

        # Try to parse error body
        try:
            err = resp.json()
        except Exception:
            err = None

        code = err.get("error", {}).get("code") if isinstance(err, dict) else None
        msg = err.get("error", {}).get("message") if isinstance(err, dict) else resp.text

        if resp.status_code == 400:
            raise BadRequestError(code or "BAD_REQUEST", msg or "Invalid request")

        if resp.status_code == 409:
            raise ConflictOutOfOrderError(code or "CONFLICT_OUT_OF_ORDER", msg or "Out-of-order ts_ms")

        if resp.status_code in (500, 503):
            raise InternalServerError(code or "INTERNAL_ERROR", msg or "Server error")

        # Fallback
        resp.raise_for_status()


class BadRequestError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class ConflictOutOfOrderError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class InternalServerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# -------------------- Replay Scheduler --------------------

class ReplayController:
    def __init__(self, client: SDLCClient, speed: float = 1.0, dry_run: bool = False,
                 max_retries: int = 3, backoff_s: float = 0.75):
        self.client = client
        self.speed = max(1e-6, float(speed))
        self.dry_run = dry_run
        self.max_retries = max_retries
        self.backoff_s = backoff_s
        self._lock = threading.Lock()
        self._snap_iter = None
        self._current = None
        self._tolerance_ms = 50

    def _load_snaps(self, ndjson_path: str):
        snaps = list(iter_ndjson(ndjson_path))
        if not snaps:
            logging.warning("No snapshots found in NDJSON file")
            return [], None
        return snaps, snaps[0].ts_ms

    def start_lidar_match_stream(self, ndjson_path: str, source: L2PcapTimeSource, tolerance_ms: int = 50):
        snaps, first_ts = self._load_snaps(ndjson_path)
        if not snaps:
            return
        self._snap_iter = iter(snaps)
        self._current = next(self._snap_iter, None)
        self._tolerance_ms = int(tolerance_ms)

        def on_ts(lidar_ts_ms: int):
            logging.debug("[on_ts]   Lidar ts_ms:%d phase=%s", lidar_ts_ms, self._current.ts_ms)
            with self._lock:
                if self._current is None:
                    logging.debug("All snapshots sent, ignoring further LiDAR timestamps.")
                    return

                snap = self._current
                diff = lidar_ts_ms - snap.ts_ms
                logging.debug("[on_ts] Lidar & NDJSON diff = %d ms", diff)

                if abs(diff) <= self._tolerance_ms:
                # if True:
                    # 命中阈值 → 发送并推进
                    if self.dry_run:
                        logging.info("[DRY-RUN][MATCH] NDJSON ts= %d, LiDAR = %d, diff= %d ms, phases= %d", snap.ts_ms, lidar_ts_ms, diff, len(snap.phases))
                    else:
                        self._send_with_retry(snap)
                    self._current = next(self._snap_iter, None)
                    return

                if diff > self._tolerance_ms:
                    # LiDAR 时间超前太多 → 认为这条 NDJSON 错过了，跳过
                    logging.warning("[MISS] LiDAR = %d ahead of NDJSON = %d by %d ms (> %d). Skip.", lidar_ts_ms, snap.ts_ms, diff, self._tolerance_ms)
                    self._current = next(self._snap_iter, None)
                    return

                # diff < -tolerance：LiDAR 还落后，继续等后续帧
                logging.debug("Waiting: LiDAR = %d behind NDJSON = %d by %d ms.", lidar_ts_ms, snap.ts_ms, -diff)

        # 把回调挂上去并启动抓包
        source.set_handler(on_ts)
        source.start()

    def _send_with_retry(self, snap: Snapshot) -> None:
        attempt = 0
        while True:
            try:
                self.client.post_snapshot(snap)
                logging.debug("Sent ts_ms=%d", snap.ts_ms)
                return
            except ConflictOutOfOrderError as e:
                logging.warning("409 out-of-order for ts_ms=%d; skipping. Detail: %s", snap.ts_ms, e)
                return
            except BadRequestError as e:
                logging.error("400 bad request for ts_ms=%d: %s", snap.ts_ms, e)
                return
            except InternalServerError as e:
                attempt += 1
                if attempt > self.max_retries:
                    logging.error("Server error after %d retries for ts_ms=%d: %s", self.max_retries, snap.ts_ms, e)
                    return
                backoff = self.backoff_s * (2 ** (attempt - 1))
                logging.warning("Server error, retrying in %.2fs (attempt %d/%d)...", backoff, attempt, self.max_retries)
                time.sleep(backoff)
            except requests.RequestException as e:
                attempt += 1
                if attempt > self.max_retries:
                    logging.error("Network error after %d retries for ts_ms=%d: %s", self.max_retries, snap.ts_ms, e)
                    return
                backoff = self.backoff_s * (2 ** (attempt - 1))
                logging.warning("Network error, retrying in %.2fs (attempt %d/%d)...", backoff, attempt, self.max_retries)
                time.sleep(backoff)



class L2PcapTimeSource:
    """
        L2 抓包 → 解析 InnoDataPacketV1 → 直接回调 on_ts(ts_ms:int)
    """
    def __init__(self, iface: str, udp_port: int, bpf: str = None, sample_rate: int = 1):
        self.iface = iface
        self.udp_port = udp_port
        self.sample_rate = max(1, int(sample_rate))
        port_expr = f"udp and port {udp_port}"
        self.bpf = f"({port_expr})" if not bpf else f"({port_expr}) and ({bpf})"
        self._sniffer = None
        self._pkt_counter = 0
        self._on_ts = None
        self._running = False
        self._last_ts_ms = None  # 可选：过滤非递增时间戳
        self._lock = threading.Lock()

    def set_handler(self, on_ts):
        """注册回调: on_ts(ts_ms:int)"""
        self._on_ts = on_ts

    def _on_packet(self, pkt):
        if UDP not in pkt or self._on_ts is None:
            return
        try:
            payload = raw(pkt[UDP].payload)
        except Exception:
            return
        
        if len(payload) < ctypes.sizeof(InnoDataPacketV1):
            logging.debug("L2: packet too small: %d", len(payload))
            return
        
        self._pkt_counter += 1
        if (self._pkt_counter % self.sample_rate) != 0:
            return
        
        # t0 = time.perf_counter()
        pkt = InnoDataPacketV1.from_buffer_copy(payload)
        # t1 = time.perf_counter()
        # logging.info(f"parse_time={(t1 - t0) * 1e6:.1f} µs")

        ts_ms = pkt.common.ts_start_us // 1e3
        logging.debug(f"L2 captured ts_ms={ts_ms}")

        # 可选：只向上递增，避免乱序
        with self._lock:
            if self._last_ts_ms is not None and ts_ms <= self._last_ts_ms:
                return
            self._last_ts_ms = ts_ms

        try:
            self._on_ts(ts_ms)
        except Exception as e:
            logging.exception("on_ts handler failed: %s", e)

    def start(self):
        if self._running:
            return
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            store=False,
            prn=self._on_packet,
            filter=self.bpf
        )
        self._sniffer.start()
        self._running = True
        logging.info("L2 sniffer started on %s (BPF: %s), sample_rate=%d",
                     self.iface, self.bpf, self.sample_rate)

    def stop(self):
        if not self._running:
            return
        try:
            self._sniffer.stop()
        finally:
            self._running = False
            logging.info("L2 sniffer stopped")

class LidarTimeSource:
    """
    Real-time LiDAR frame receiver that extracts timestamps from UDP packets.
    
    Receives UDP packets containing LiDAR frames with InnoCommonHeader,
    extracts ts_start_us timestamps, and provides them as time source for replay.
    """
    
    def __init__(self, udp_port: int = 8011, buffer_size: int = 65536, 
                 bind_addr: str = "0.0.0.0", timeout: float = 1.0):
        self.udp_port = udp_port
        self.buffer_size = buffer_size
        self.bind_addr = bind_addr
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._running = False
        
    def start(self) -> None:
        """Initialize UDP socket and start listening."""
        if self._socket is not None:
            return
            
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.settimeout(self.timeout)
        
        try:
            self._socket.bind((self.bind_addr, self.udp_port))
            self._running = True
            logging.info(f"LidarTimeSource listening on {self.bind_addr}:{self.udp_port}")
        except Exception as e:
            self._socket.close()
            self._socket = None
            raise RuntimeError(f"Failed to bind UDP socket: {e}")
    
    def stop(self) -> None:
        """Stop listening and close socket."""
        self._running = False
        if self._socket:
            self._socket.close()
            self._socket = None
            logging.info("LidarTimeSource stopped")

# -------------------- CLI --------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Replay phase snapshots to SDLC.")
    p.add_argument("--base-url", required=True, help="Base URL of SDLC service, e.g. http://127.0.0.1:8000")
    p.add_argument("--file", help="Path to NDJSON record file to replay")
    p.add_argument("--speed", type=float, default=1.0, help="Replay speed factor (1.0 = real-time)")
    p.add_argument("--token", default="", help="Bearer token for auth (optional)")
    p.add_argument("--dry-run", action="store_true", help="Do not POST, just log what would be sent")
    p.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    p.add_argument("--retries", type=int, default=3, help="Max retries for transient errors")
    p.add_argument("--backoff", type=float, default=0.75, help="Initial backoff seconds for retries")
    
    # LiDAR-related options
    p.add_argument("--lidar-mode", choices=["real", "fake"], help="Choose lidar mode: 'real' = auto-discover real lidar NIC, 'fake' = discover on specified subnet")
    p.add_argument("--fake-subnet", help="Required when --lidar-mode=fake, e.g. 172.16.210.0/24")
    p.add_argument("--lidar-port", type=int, default=8011, help="UDP port for LiDAR data (default: 8011)")
    
    # L2 capture options
    p.add_argument("--l2-iface", help="Network interface for L2 packet capture (e.g., eth0)")
    p.add_argument("--l2-bpf", help="Custom BPF filter for L2 capture (default: udp and port <lidar-port>)")
    
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(funcName)s | %(message)s",
    )

    if not args.file:
        logging.error("Please specify --file <record.ndjson> for NDJSON replay.")
        return 2

    # ---- construct client & controller ----
    client = SDLCClient(base_url=args.base_url, token=(args.token or None))
    ctrl = ReplayController(
        client,
        speed=args.speed,
        dry_run=args.dry_run,
        max_retries=args.retries,
        backoff_s=args.backoff,
    )

    # ---- LiDAR source with callback ----
    if args.lidar_mode == "real":
        l2_iface = discovery_live_lidar_interface()
        # check interface validity
        if not l2_iface:
            logging.error("Failed to discover real LiDAR interface. ")
            return 2
    elif args.lidar_mode == "fake":
        if not args.fake_subnet:
            logging.error("Please specify --fake-subnet (e.g. 172.16.210.0/24) when --lidar-mode=fake.")
            return 2
        l2_iface = discovery_fake_lidar_interface(args.fake_subnet)
        if not l2_iface:
            logging.error("Failed to discover fake LiDAR interface. ")
            return 2
        else:
            logging.info(f"Using fake LiDAR interface: {l2_iface}")
    else:
        logging.error("Please specify --lidar-mode as 'real' or 'fake'.")
        return 2

    logging.info(f"Using LiDAR interface: {l2_iface}")
    source = L2PcapTimeSource(
        iface=l2_iface,
        udp_port=args.lidar_port,
        bpf=args.l2_bpf,
        sample_rate= 100,
    )
    
    try:
        ctrl.start_lidar_match_stream(args.file, source, tolerance_ms=50)
        logging.info("LiDAR-match stream started. Press Ctrl-C to stop.")
        # main thread just sleeps
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logging.info("Interrupted by user, shutting down...")
        try:
            source.stop()
        except Exception:
            pass
        return 0
    except Exception as e:
        logging.exception("Fatal error: %s", e)
        try:
            source.stop()
        except Exception:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
