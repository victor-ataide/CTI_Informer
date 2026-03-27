import json
import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Any
from dotenv import load_dotenv

from .deduplicator import ThreatDeduplicator

# Carregar .env
load_dotenv()


def _get_ioc_hash(iocs: Dict) -> str:
    if not iocs:
        return ""
    return ThreatDeduplicator()._generate_ioc_hash(iocs)


def connect_db(db_config: Dict[str, Any]) -> Any:
    engine = db_config.get("engine", "sqlite").lower()

    if engine == "postgresql":
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError as e:
            raise ImportError("psycopg2 is required for PostgreSQL. Instale: pip install psycopg2-binary") from e

        pg = db_config.get("postgresql", {})
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST", pg.get("host", "localhost")),
            port=int(os.getenv("POSTGRES_PORT", pg.get("port", 5432))),
            dbname=os.getenv("POSTGRES_DBNAME", pg.get("dbname", "cti")),
            user=os.getenv("POSTGRES_USER", pg.get("user", "")),
            password=os.getenv("POSTGRES_PASSWORD", pg.get("password", "")),
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        return conn

    # Default: SQLite local
    sqlite_path = db_config.get("sqlite_path", "data/cti_threats.db")
    Path(os.path.dirname(sqlite_path) or ".").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(sqlite_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: Any, db_config: Dict[str, Any]) -> None:
    engine = db_config.get("engine", "sqlite").lower()

    if engine == "postgresql":
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                ioc_hash TEXT UNIQUE,
                timestamp TEXT,
                title TEXT,
                severity TEXT,
                apt_groups TEXT,
                malware_names TEXT,
                affected_sectors TEXT,
                affected_countries TEXT,
                source TEXT,
                payload TEXT
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threats(timestamp)")
        conn.commit()
        return

    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_hash TEXT UNIQUE,
            timestamp TEXT,
            title TEXT,
            severity TEXT,
            apt_groups TEXT,
            malware_names TEXT,
            affected_sectors TEXT,
            affected_countries TEXT,
            source TEXT,
            payload TEXT
        )
        """
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threats(timestamp)")
    conn.commit()


def _normalize_list_field(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in sorted(set(value)) if v is not None)
    return str(value)


def save_threats_to_db(threats: List[Dict[str, Any]], db_config: Dict[str, Any]) -> int:
    conn = connect_db(db_config)
    init_db(conn, db_config)

    engine = db_config.get("engine", "sqlite").lower()
    inserted = 0
    cursor = conn.cursor()

    for threat in threats:
        iocs = threat.get("iocs", {})
        ioc_hash = _get_ioc_hash(iocs)

        if not ioc_hash:
            continue

        threat_info = threat.get("threat_info", {}) or {}

        data = {
            "ioc_hash": ioc_hash,
            "timestamp": threat.get("timestamp", ""),
            "title": threat.get("title") or threat.get("source", {}).get("title", ""),
            "severity": threat_info.get("severity", "desconhecida"),
            "apt_groups": _normalize_list_field(threat_info.get("apt_groups", [])),
            "malware_names": _normalize_list_field(threat_info.get("malware_names", [])),
            "affected_sectors": _normalize_list_field(threat_info.get("affected_sectors", [])),
            "affected_countries": _normalize_list_field(threat.get("affected_countries", [])),
            "source": (threat.get("source", {}).get("name") if isinstance(threat.get("source"), dict) else ""),
            "payload": json.dumps(threat, ensure_ascii=False)
        }

        if engine == "postgresql":
            cursor.execute(
                """
                INSERT INTO threats (ioc_hash, timestamp, title, severity, apt_groups, malware_names, affected_sectors, affected_countries, source, payload)
                VALUES (%(ioc_hash)s, %(timestamp)s, %(title)s, %(severity)s, %(apt_groups)s, %(malware_names)s, %(affected_sectors)s, %(affected_countries)s, %(source)s, %(payload)s)
                ON CONFLICT (ioc_hash) DO NOTHING
                """,
                data
            )

        else:
            cursor.execute(
                """
                INSERT OR IGNORE INTO threats (ioc_hash, timestamp, title, severity, apt_groups, malware_names, affected_sectors, affected_countries, source, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["ioc_hash"], data["timestamp"], data["title"], data["severity"],
                    data["apt_groups"], data["malware_names"], data["affected_sectors"],
                    data["affected_countries"], data["source"], data["payload"]
                )
            )

        if conn.total_changes if engine == "sqlite" else cursor.rowcount:
            inserted += 1

    conn.commit()
    conn.close()
    return inserted


def load_threats_from_db(db_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    if db_config.get("engine", "sqlite").lower() == "sqlite" and not os.path.exists(db_config.get("sqlite_path", "data/cti_threats.db")):
        return []

    conn = connect_db(db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT payload FROM threats ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        payload = r[0] if isinstance(r, tuple) else r.get("payload")
        try:
            result.append(json.loads(payload))
        except Exception:
            continue

    return result
