"""
Central in-memory state shared by packet capture, demo generator,
and FastAPI endpoints.

Handles:
- Live traffic statistics
- Active connections
- Live events
- Capture status
- Last AI decision
- WebSocket dashboard snapshots

All shared mutable state is guarded by locks so it can be read and
updated safely from the packet-capture thread, the flow-predictor
thread, the demo thread, and the FastAPI worker threads at once.
"""

import time
import threading
from collections import deque

from database import insert_event


# ===============================================================
# LIVE TRAFFIC
# ===============================================================

TRAFFIC_WINDOW = 600

traffic_series = deque(maxlen=TRAFFIC_WINDOW)

traffic_lock = threading.Lock()


_current = {
    "second_started": time.time(),

    "tcp": 0,
    "udp": 0,
    "other": 0,

    "benign": 0,
    "attacks": 0,

    "packets": 0,
}


# ===============================================================
# ACTIVE CONNECTIONS
# ===============================================================

active_connections = {}

connections_lock = threading.Lock()

_last_conn_cleanup = 0.0

CONNECTION_CLEANUP_INTERVAL = 15.0


# ===============================================================
# LIVE EVENTS
# ===============================================================

recent_events = deque(maxlen=200)


# ===============================================================
# CAPTURE STATUS
# ===============================================================

capture_status = {
    "running": False,
    "mode": "idle",
    "iface": "Wi-Fi",
    "started_at": None,
    "packets_seen": 0,
    "last_heartbeat": None,
    "error": None,
}

capture_lock = threading.Lock()


def update_capture_status(**fields):
    """Atomically update the shared capture_status dict."""
    with capture_lock:
        capture_status.update(fields)


# ===============================================================
# LAST AI DECISION
# ===============================================================

last_ai_decision = {

    "prediction": None,

    "confidence": None,

    "explanation": [],

    "features": {},

    "flow": {},

    "timestamp": None,
}

ai_decision_lock = threading.Lock()


def set_ai_decision(**fields):
    """Atomically update the AI Decision Engine state."""
    with ai_decision_lock:
        last_ai_decision.update(fields)


def get_ai_decision():
    """Return a thread-safe shallow copy of the AI Decision state."""
    with ai_decision_lock:
        return dict(last_ai_decision)


# ===============================================================
# RECORD PACKET
# ===============================================================

def record_packet(
    protocol,
    attack,
    packet_size,
    flow,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    tcp_flags=""
):
    """
    Record a processed packet into live dashboard state.
    """

    now = time.time()

    # -----------------------------------------------------------
    # Traffic statistics
    # -----------------------------------------------------------

    with traffic_lock:

        if (
            now -
            _current["second_started"]
            >= 1.0
        ):

            _flush_second()

        _current["packets"] += 1

        protocol_lower = protocol.lower()

        if protocol_lower == "tcp":

            _current["tcp"] += 1

        elif protocol_lower == "udp":

            _current["udp"] += 1

        else:

            # ICMP and other protocols
            _current["other"] += 1

        # -------------------------------------------------------
        # Attack counter
        # -------------------------------------------------------

        if attack == "BENIGN":

            _current["benign"] += 1

        else:

            _current["attacks"] += 1

    # -----------------------------------------------------------
    # Active connections
    # -----------------------------------------------------------

    global _last_conn_cleanup

    with connections_lock:

        key = (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

        existing = active_connections.get(key)

        if existing:

            existing["packets"] += 1

            existing["bytes"] += packet_size

            existing["last_seen"] = now

            existing["attack_type"] = attack

            if tcp_flags:

                existing[
                    "tcp_flags"
                ] = tcp_flags

        else:

            active_connections[key] = {

                "source_ip":
                    src_ip,

                "destination_ip":
                    dst_ip,

                "source_port":
                    src_port,

                "destination_port":
                    dst_port,

                "protocol":
                    protocol,

                "packets":
                    1,

                "bytes":
                    packet_size,

                "first_seen":
                    now,

                "last_seen":
                    now,

                "attack_type":
                    attack,

                "tcp_flags":
                    tcp_flags,
            }

        # -------------------------------------------------------
        # Remove connections older than 60 seconds.
        # Only run this scan every few seconds so the per-packet
        # hot path stays O(1).
        # -------------------------------------------------------

        if now - _last_conn_cleanup >= CONNECTION_CLEANUP_INTERVAL:

            _last_conn_cleanup = now

            stale = [

                k

                for k, v
                in active_connections.items()

                if now - v["last_seen"] > 60

            ]

            for k in stale:

                del active_connections[k]


# ===============================================================
# FLUSH ONE SECOND
# ===============================================================

def _flush_second():

    now = time.time()

    previous = (
        _current["second_started"]
    )

    traffic_series.append({

        "t":
            int(previous),

        "ts":
            time.strftime(
                "%H:%M:%S",
                time.localtime(previous)
            ),

        "tcp":
            _current["tcp"],

        "udp":
            _current["udp"],

        "other":
            _current["other"],

        "benign":
            _current["benign"],

        "attacks":
            _current["attacks"],

        "packets":
            _current["packets"],
    })

    _current["second_started"] = now

    _current["tcp"] = 0

    _current["udp"] = 0

    _current["other"] = 0

    _current["benign"] = 0

    _current["attacks"] = 0

    _current["packets"] = 0


# ===============================================================
# FLUSH TRAFFIC
# ===============================================================

def flush_traffic():

    with traffic_lock:

        if (
            _current["packets"] > 0
            or
            len(traffic_series) == 0
        ):

            _flush_second()


# ===============================================================
# RESET STATE
# ===============================================================

def reset_state():

    global _current
    global _last_conn_cleanup

    with traffic_lock:

        traffic_series.clear()

        _current = {

            "second_started":
                time.time(),

            "tcp":
                0,

            "udp":
                0,

            "other":
                0,

            "benign":
                0,

            "attacks":
                0,

            "packets":
                0,
        }

    with connections_lock:

        active_connections.clear()

        _last_conn_cleanup = 0.0

    recent_events.clear()

    update_capture_status(
        packets_seen=0,
        last_heartbeat=None,
        error=None,
    )

    set_ai_decision(
        prediction=None,
        confidence=None,
        explanation=[],
        features={},
        flow={},
        timestamp=None,
    )

    with _snapshot_lock:

        _snapshot_cache = None
        _snapshot_cached_at = 0.0


# ===============================================================
# EVENT LOG
# ===============================================================

def log_event(
    stage,
    message,
    details=""
):
    """
    Add event to live dashboard and database.
    """

    entry = {

        "timestamp":
            time.strftime(
                "%H:%M:%S"
            ),

        "stage":
            stage,

        "message":
            message,

        "details":
            details,
    }

    recent_events.appendleft(entry)

    try:

        insert_event(
            stage,
            message,
            details
        )

    except Exception:

        # Database logging is best effort
        pass


# ===============================================================
# LIVE STATE
# ===============================================================

def get_live_state():

    with traffic_lock:

        has_packets = (
            _current["packets"] > 0
        )

    if has_packets:

        flush_traffic()

    now = time.time()

    series = list(
        traffic_series
    )

    # -----------------------------------------------------------
    # Copy connections safely
    # -----------------------------------------------------------

    with connections_lock:

        conns = [
            dict(v)
            for v
            in active_connections.values()
        ]

    for connection in conns:

        connection["age"] = round(

            now -
            connection["last_seen"],

            1
        )

    return {

        "traffic":
            series,

        "connections":
            conns,

        "events":
            list(recent_events),

        "status":
            dict(capture_status),
    }


# ===============================================================
# WEBSOCKET CONNECTION MANAGER
# ===============================================================

class ConnectionManager:

    def __init__(self):

        self._connections = set()

        self._lock = threading.Lock()

    async def connect(
        self,
        websocket
    ):

        await websocket.accept()

        with self._lock:

            self._connections.add(
                websocket
            )

    def disconnect(
        self,
        websocket
    ):

        with self._lock:

            self._connections.discard(
                websocket
            )

    @property
    def count(self):

        with self._lock:

            return len(
                self._connections
            )

    async def broadcast(
        self,
        message
    ):

        dead = []

        with self._lock:

            clients = list(
                self._connections
            )

        for websocket in clients:

            try:

                await websocket.send_json(
                    message
                )

            except Exception:

                dead.append(
                    websocket
                )

        for websocket in dead:

            self.disconnect(
                websocket
            )


manager = ConnectionManager()


# ===============================================================
# DASHBOARD SNAPSHOT CACHE
# ===============================================================

_snapshot_lock = threading.Lock()
_snapshot_cache = None
_snapshot_cached_at = 0.0

SNAPSHOT_TTL = 2.0


def _cached_snapshot():
    """Return the cached snapshot if it is still fresh."""
    global _snapshot_cache, _snapshot_cached_at
    now = time.time()
    with _snapshot_lock:
        if (
            _snapshot_cache is not None
            and now - _snapshot_cached_at < SNAPSHOT_TTL
        ):
            return _snapshot_cache
    return None


def _store_snapshot(snapshot):
    global _snapshot_cache, _snapshot_cached_at
    with _snapshot_lock:
        _snapshot_cache = snapshot
        _snapshot_cached_at = time.time()


# ===============================================================
# BUILD DASHBOARD SNAPSHOT
# ===============================================================

def build_snapshot(force=False):

    # Reuse the last snapshot if it is still fresh. This stops the
    # WebSocket broadcaster from hitting the database every tick.
    if not force:
        cached = _cached_snapshot()
        if cached is not None:
            return cached

    state = get_live_state()

    series = state["traffic"]

    # -----------------------------------------------------------
    # Dashboard graph: last 60 seconds
    # -----------------------------------------------------------

    if series:

        state["traffic"] = series[-60:]


    # ===========================================================
    # DATABASE INFORMATION
    # ===========================================================

    stats = None

    latest = None

    latest_threat = None

    alerts = []

    try:

        from database import get_connection

        conn = get_connection()

        # -------------------------------------------------------
        # Total predictions
        # -------------------------------------------------------

        total = conn.execute(
            "SELECT COUNT(*) FROM threats"
        ).fetchone()[0]

        # -------------------------------------------------------
        # Benign predictions
        # -------------------------------------------------------

        benign = conn.execute(
            """
            SELECT COUNT(*)
            FROM threats
            WHERE attack_type='BENIGN'
            """
        ).fetchone()[0]

        # -------------------------------------------------------
        # Recent attacks
        # -------------------------------------------------------

        recent_attacks = conn.execute(
            """
            SELECT COUNT(*)
            FROM (
                SELECT attack_type
                FROM threats
                ORDER BY id DESC
                LIMIT 100
            )
            WHERE attack_type != 'BENIGN'
            """
        ).fetchone()[0]

        attacks = total - benign

        # -------------------------------------------------------
        # Database threat level
        # -------------------------------------------------------

        if recent_attacks == 0:

            threat_level = "SAFE"

            severity = 20

        elif recent_attacks <= 5:

            threat_level = "WARNING"

            severity = 60

        else:

            threat_level = "CRITICAL"

            severity = 100


        # -------------------------------------------------------
        # Latest prediction
        # -------------------------------------------------------

        latest = conn.execute(

            """
            SELECT *
            FROM threats
            ORDER BY id DESC
            LIMIT 1
            """

        ).fetchone()


        # -------------------------------------------------------
        # Latest threat
        # -------------------------------------------------------

        latest_threat = conn.execute(

            """
            SELECT *
            FROM threats
            WHERE attack_type != 'BENIGN'
            ORDER BY id DESC
            LIMIT 1
            """

        ).fetchone()


        # -------------------------------------------------------
        # Recent alerts
        # -------------------------------------------------------

        alert_rows = conn.execute(

            """
            SELECT *
            FROM threats
            WHERE attack_type != 'BENIGN'
            ORDER BY id DESC
            LIMIT 6
            """

        ).fetchall()


        alerts = [
            dict(row)
            for row
            in alert_rows
        ]


        stats = {

            "total_predictions":
                total,

            "benign":
                benign,

            "attacks":
                attacks,

            "recent_attacks":
                recent_attacks,

            "threat_level":
                threat_level,

            "severity":
                severity,
        }


        conn.close()

    except Exception:

        pass


    # ===========================================================
    # LIVE AI OVERRIDE
    # ===========================================================

    # Even if the database query has not refreshed yet,
    # the dashboard immediately reacts to the latest live
    # AI/behavioral prediction.

    decision = get_ai_decision()

    live_prediction = (
        decision.get(
            "prediction"
        )
    )

    live_confidence = (
        decision.get(
            "confidence"
        )
    )

    live_timestamp = (
        decision.get(
            "timestamp"
        )
    )


    if (

        live_prediction

        and

        live_prediction != "BENIGN"

    ):

        # -------------------------------------------------------
        # Force dashboard into threat state
        # -------------------------------------------------------

        if stats is None:

            stats = {

                "total_predictions":
                    0,

                "benign":
                    0,

                "attacks":
                    0,

                "recent_attacks":
                    0,

                "threat_level":
                    "CRITICAL",

                "severity":
                    100,
            }

        else:

            stats["threat_level"] = (
                "CRITICAL"
            )

            stats["severity"] = 100

        # -------------------------------------------------------
        # If database latest threat is empty,
        # construct a live threat object.
        # -------------------------------------------------------

        if not latest_threat:

            latest_threat = {

                "attack_type":
                    live_prediction,

                "confidence":
                    live_confidence,

                "severity":
                    "HIGH",

                "timestamp":
                    live_timestamp,
            }


    # ===========================================================
    # AI EXPLANATION
    # ===========================================================

    from alerts import enrich_prediction

    ai = None


    if decision.get(
        "prediction"
    ):

        try:

            from explainer import explain

            result = explain(

                decision[
                    "prediction"
                ],

                decision[
                    "confidence"
                ],

                decision[
                    "features"
                ],
            )

            result[
                "timestamp"
            ] = decision.get(
                "timestamp"
            )

            result[
                "prediction"
            ] = result[
                "attack"
            ]

            ai = result

        except Exception:

            # If the explainer fails,
            # still provide basic AI information.

            ai = {

                "attack":
                    live_prediction,

                "prediction":
                    live_prediction,

                "confidence":
                    live_confidence,

                "timestamp":
                    live_timestamp,

                "explanation":
                    [],
            }


    # ===========================================================
    # FINAL SNAPSHOT
    # ===========================================================

    snapshot = {

        "ts":
            time.time(),

        "traffic":
            state["traffic"],

        "connections":
            state["connections"],

        "events":
            state["events"][:60],

        "status":
            state["status"],

        "stats":
            stats,

        "latest":
            (
                enrich_prediction(
                    dict(latest)
                )
                if latest
                else {}
            ),

        "latest_threat":
            (
                enrich_prediction(
                    dict(latest_threat)
                )
                if latest_threat
                else {}
            ),

        "alerts":
            [
                enrich_prediction(
                    a
                )
                for a in alerts
            ],

        "ai":
            ai,
    }

    _store_snapshot(snapshot)

    return snapshot