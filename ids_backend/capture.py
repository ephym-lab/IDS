"""
capture.py
----------
Live packet capture using Scapy in a background daemon thread.

Each captured packet is:
  1. Parsed to extract a best-effort set of UNSW-NB15 features
  2. Preprocessed + run through the model
  3. Stored in the DB (log + optional alert)

Email notification rules (mirrors main.py — no circular import)
---------------------------------------------------------------
  - High severity   → always notify all registered users
  - Medium severity → notify only when confidence > 60%
  - Low severity    → never notify

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
from logging.handlers import RotatingFileHandler

import email_service

logger = logging.getLogger(__name__)

# Scapy emits a noisy "Unable to guess type" WARNING for non-IP frames
# (ARP, 802.11 management frames, etc.) seen on Wi-Fi interfaces.
# These packets are already filtered out by the `if not pkt.haslayer(IP)`
# guard in _extract_features(), so the warning is benign.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

_stop_event = threading.Event()
_capture_thread: threading.Thread | None = None

# Track per-flow stats for derived features (simplified)
_flow_table: dict[tuple, dict] = {}
_flow_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Rotating file handler for capture logs
# ---------------------------------------------------------------------------

def _setup_capture_logger() -> None:
    """
    Attach a rotating file handler to the capture logger so packet-level
    logs are written to ids_capture.log without flooding the console.
    Keeps up to 3 files of 5 MB each.
    """
    if any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        return  # already set up
    handler = RotatingFileHandler(
        "ids_capture.log", maxBytes=5_000_000, backupCount=3
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Email helper — local copy to avoid circular import with main.py
# ---------------------------------------------------------------------------

def _should_email(severity: str, confidence: float) -> bool:
    """
    Return True if this detection warrants an email notification.

    Rules:
      - High severity   → always notify (regardless of confidence)
      - Medium severity → notify only when confidence > 60%
      - Low severity    → never notify
    """
    if severity == "High":
        return True
    if severity == "Medium" and confidence > 0.60:
        return True
    return False


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

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
            if flags & 0x01:    # FIN
                state = "FIN"
            elif flags & 0x04:  # RST
                state = "RST"
            elif flags & 0x02:  # SYN
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
            if sport == 53 or dport == 53:   service = "dns"
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
            # Ports stored for logging
            "sport": sport,
            "dport": dport,
        }
        return features

    except Exception as exc:  # noqa: BLE001
        logger.debug("Feature extraction error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Capture loop
# ---------------------------------------------------------------------------

def _run_capture(loop: asyncio.AbstractEventLoop) -> None:
    """
    Blocking Scapy sniff loop. Runs in the background daemon thread.
    For each packet: extract features -> preprocess -> predict -> DB insert.
    """
    from scapy.sendrecv import sniff
    import database
    import model as mdl
    import preprocessor

    def _handle_packet(pkt) -> None:
        print(f"RAW PACKET: {pkt.summary()}")
        features = _extract_features(pkt)
        if features is None:
            return

        logger.info(
            "Packet captured: %s -> %s | proto=%s sport=%s dport=%s bytes=%s",
            features["src_ip"], features["dst_ip"],
            features["proto"], features["sport"],
            features["dport"], features["sbytes"],
        )

        try:
            arr = preprocessor.preprocess(features)
            logger.debug("Preprocessed features array: %s", arr)

            class_label, confidence = mdl.predict(arr)
            is_attack = class_label != "Normal"
            severity = database.get_severity(class_label) if is_attack else None

            logger.info(
                "Prediction: %s -> %s | class=%s confidence=%.4f is_attack=%s",
                features["src_ip"], features["dst_ip"],
                class_label, confidence, is_attack,
            )

            if is_attack:
                logger.warning(
                    "ATTACK DETECTED: %s -> %s | type=%s severity=%s confidence=%.4f",
                    features["src_ip"], features["dst_ip"],
                    class_label, severity, confidence,
                )

            asyncio.run_coroutine_threadsafe(
                database.insert_log(
                    src_ip=features["src_ip"],
                    dst_ip=features["dst_ip"],
                    proto=features["proto"],
                    predicted_class=class_label,
                    confidence=confidence,
                    is_attack=is_attack,
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
                    ),
                    loop,
                )

                if severity and _should_email(severity, confidence):
                    ts = datetime.now(timezone.utc).isoformat()

                    async def _notify():
                        recipients = await database.get_all_user_emails()
                        if recipients:
                            await email_service.notify_alert(
                                attack_type=class_label,
                                severity=severity,
                                src_ip=features["src_ip"],
                                dst_ip=features["dst_ip"],
                                confidence=confidence,
                                timestamp=ts,
                                recipients=recipients,
                            )

                    asyncio.run_coroutine_threadsafe(_notify(), loop)
                    logger.info(
                        "Email notification queued for attack: type=%s severity=%s",
                        class_label, severity,
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_capture(loop: asyncio.AbstractEventLoop) -> bool:
    """
    Start the background capture thread (idempotent).

    Parameters
    ----------
    loop : asyncio.AbstractEventLoop
        The running FastAPI event loop, used for scheduling async DB writes.

    Returns
    -------
    bool  True if newly started, False if already running.
    """
    global _capture_thread, _stop_event

    if _capture_thread is not None and _capture_thread.is_alive():
        return False  # already running

    _setup_capture_logger()
    _stop_event.clear()
    _capture_thread = threading.Thread(
        target=_run_capture,
        args=(loop,),
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
    global _capture_thread

    if _capture_thread is None or not _capture_thread.is_alive():
        return False

    _stop_event.set()
    _capture_thread.join(timeout=5)
    _capture_thread = None
    return True


def is_capturing() -> bool:
    return _capture_thread is not None and _capture_thread.is_alive()