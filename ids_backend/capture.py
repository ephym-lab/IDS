"""
capture.py
----------
Live packet capture using Scapy in a background daemon thread.

Each captured packet is:
  1. Parsed to extract a best-effort set of UNSW-NB15 features
  2. Preprocessed + run through the model
  3. Stored in the DB (log + optional alert)

Usage
-----
    from capture import start_capture, stop_capture

    start_capture()   # non-blocking; starts daemon thread
    stop_capture()    # signals the thread to stop
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_stop_event = threading.Event()
_capture_thread: threading.Thread | None = None

# user_id of whoever called start_capture(); used to tag every DB row
_session_user_id: int | None = None

# Track per-flow stats for derived features (simplified)
_flow_table: dict[tuple, dict] = {}
_flow_lock = threading.Lock()


def _extract_features(pkt) -> dict | None:
    """
    Parse a Scapy packet into a UNSW-NB15 style feature dict.
    Fields that cannot be derived are defaulted to 0.
    Returns None if the packet is too small to be meaningful.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import ARP

        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        src_ip: str = ip.src
        dst_ip: str = ip.dst
        proto_num: int = ip.proto
        pkt_len: int = len(pkt)

        # Map IP protocol number -> UNSW-NB15 proto string
        proto_map = {6: "tcp", 17: "udp", 1: "icmp", 41: "ipv6"}
        proto = proto_map.get(proto_num, str(proto_num))

        # State / service / port defaults
        state = "INT"
        service = "-"
        sport, dport = 0, 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            if flags & 0x01:   # FIN
                state = "FIN"
            elif flags & 0x04: # RST
                state = "RST"
            elif flags & 0x02: # SYN
                state = "CON"
            # Rough service detection
            for port in (sport, dport):
                if port == 80:    service = "http"
                elif port == 443: service = "ssl"
                elif port == 22:  service = "ssh"
                elif port == 21:  service = "ftp"
                elif port == 25:  service = "smtp"
                elif port == 53:  service = "dns"
                elif port == 110: service = "pop3"
                elif port == 143: service = "irc"

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            state = "CON"
            if sport == 53 or dport == 53: service = "dns"
            elif sport == 67 or dport == 67: service = "dhcp"

        elif pkt.haslayer(ICMP):
            state = "CON"

        # Per-flow tracking key
        flow_key = (src_ip, dst_ip, proto, sport, dport)
        now = time.time()

        with _flow_lock:
            if flow_key not in _flow_table:
                _flow_table[flow_key] = {
                    "start": now,
                    "spkts": 0, "dpkts": 0,
                    "sbytes": 0, "dbytes": 0,
                    "last_src": now,
                }
            flow = _flow_table[flow_key]

            # Determine direction (simplified: first pkt -> src)
            flow["spkts"] += 1
            flow["sbytes"] += pkt_len
            dur = max(now - flow["start"], 1e-6)
            sinpkt = (now - flow["last_src"]) * 1000  # ms
            flow["last_src"] = now

        features = {
            # Numerical
            "dur": round(dur, 6),
            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],
            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],
            "rate": round(flow["spkts"] / dur, 4),
            "sttl": int(ip.ttl),
            "dttl": 0,
            "sload": round((flow["sbytes"] * 8) / dur, 4),
            "dload": 0.0,
            "sinpkt": round(sinpkt, 4),
            "dinpkt": 0.0,
            "sjit": 0.0,
            "djit": 0.0,
            "swin": int(pkt[TCP].window) if pkt.haslayer(TCP) else 0,
            "stcpb": 0,
            "dtcpb": 0,
            "dwin": 0,
            "smean": round(flow["sbytes"] / max(flow["spkts"], 1), 2),
            "dmean": 0.0,
            "ct_srv_src": 1,
            "ct_state_ttl": 1,
            "ct_dst_ltm": 1,
            "ct_src_dport_ltm": 1,
            "ct_dst_sport_ltm": 1,
            "ct_dst_src_ltm": 1,
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 0,
            "ct_src_ltm": 1,
            "ct_srv_dst": 1,
            "is_sm_ips_ports": int(sport == dport),
            # Categorical
            "proto": proto,
            "service": service,
            "state": state,
            # Metadata (not used for inference)
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }
        return features

    except Exception as exc:  # noqa: BLE001
        logger.debug("Feature extraction error: %s", exc)
        return None


def _run_capture(loop: asyncio.AbstractEventLoop, user_id: int | None) -> None:
    """
    Blocking Scapy sniff loop. Runs in the background daemon thread.
    For each packet: extract features -> preprocess -> predict -> DB insert.
    All rows are tagged with *user_id* so they appear on the correct dashboard.
    """
    from scapy.sendrecv import sniff
    import database
    import model as mdl
    import preprocessor

    def _handle_packet(pkt) -> None:
        features = _extract_features(pkt)
        if features is None:
            return

        try:
            arr = preprocessor.preprocess(features)
            class_label, confidence = mdl.predict(arr)
            is_attack = class_label != "Normal"

            # Schedule async DB writes on the FastAPI event loop
            asyncio.run_coroutine_threadsafe(
                database.insert_log(
                    src_ip=features["src_ip"],
                    dst_ip=features["dst_ip"],
                    proto=features["proto"],
                    predicted_class=class_label,
                    confidence=confidence,
                    is_attack=is_attack,
                    user_id=user_id,
                ),
                loop,
            )
            if is_attack:
                asyncio.run_coroutine_threadsafe(
                    database.insert_alert(
                        src_ip=features["src_ip"],
                        dst_ip=features["dst_ip"],
                        attack_type=class_label,
                        confidence=confidence,
                        user_id=user_id,
                    ),
                    loop,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Prediction pipeline error: %s", exc)

    logger.info("Packet capture started.")
    sniff(
        prn=_handle_packet,
        store=False,
        stop_filter=lambda _: _stop_event.is_set(),
    )
    logger.info("Packet capture stopped.")


def start_capture(loop: asyncio.AbstractEventLoop, user_id: int | None = None) -> bool:
    """
    Start the background capture thread (idempotent).

    Parameters
    ----------
    loop : asyncio.AbstractEventLoop
        The running FastAPI event loop, used for scheduling async DB writes.
    user_id : int | None
        The authenticated user who started this capture session.
        Every log/alert row inserted during this session will carry this id.

    Returns
    -------
    bool  True if newly started, False if already running.
    """
    global _capture_thread, _stop_event, _session_user_id

    if _capture_thread is not None and _capture_thread.is_alive():
        return False  # already running

    _session_user_id = user_id
    _stop_event.clear()
    _capture_thread = threading.Thread(
        target=_run_capture,
        args=(loop, user_id),
        daemon=True,
        name="ids-capture",
    )
    _capture_thread.start()
    return True


def stop_capture() -> bool:
    """
    Signal the capture thread to stop.

    Returns
    -------
    bool  True if it was running, False if it was already stopped.
    """
    global _capture_thread, _session_user_id

    if _capture_thread is None or not _capture_thread.is_alive():
        return False

    _stop_event.set()
    _capture_thread.join(timeout=5)
    _capture_thread = None
    _session_user_id = None
    return True


def is_capturing() -> bool:
    return _capture_thread is not None and _capture_thread.is_alive()
