"""Automated network asset discovery and service inventory application."""

from __future__ import annotations

import ipaddress
import os
import secrets
import sqlite3
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Settings:
    database_path: Path
    allowed_networks: tuple[ipaddress._BaseNetwork, ...]
    api_key: str
    scan_interval_seconds: int
    nmap_path: str = "nmap"

    @classmethod
    def from_environment(cls) -> "Settings":
        raw_networks = os.getenv("ASSET_DISCOVERY_NETWORKS", "")
        if not raw_networks.strip():
            raise ValueError("ASSET_DISCOVERY_NETWORKS must contain at least one CIDR")
        networks = []
        for value in raw_networks.split(","):
            try:
                network = ipaddress.ip_network(value.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid authorized network: {value}") from exc
            networks.append(network)
        api_key = os.getenv("ASSET_DISCOVERY_API_KEY", "")
        if len(api_key) < 16:
            raise ValueError("ASSET_DISCOVERY_API_KEY must be at least 16 characters")
        try:
            interval = max(0, int(os.getenv("ASSET_DISCOVERY_SCAN_INTERVAL_SECONDS", "0")))
        except ValueError as exc:
            raise ValueError("ASSET_DISCOVERY_SCAN_INTERVAL_SECONDS must be an integer") from exc
        database = Path(os.getenv("ASSET_DISCOVERY_DB_PATH", str(BASE_DIR / "data" / "inventory.db")))
        if not database.is_absolute():
            database = BASE_DIR / database
        return cls(database, tuple(networks), api_key, interval, os.getenv("NMAP_PATH", "nmap"))

    def authorize_target(self, target: str) -> ipaddress._BaseNetwork:
        """Return a validated network. Hosts and networks must be fully allowlisted."""
        try:
            requested = ipaddress.ip_network(target.strip(), strict=False)
        except ValueError as exc:
            raise ValueError("Target must be a valid IPv4 or IPv6 CIDR") from exc
        if not any(requested.subnet_of(allowed) for allowed in self.allowed_networks):
            raise PermissionError(f"Target {target} is outside the authorized network allowlist")
        return requested


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT,
    status TEXT NOT NULL, error TEXT, devices_found INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE, hostname TEXT, mac_address TEXT,
    vendor TEXT, last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'up'
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL, protocol TEXT NOT NULL, service_name TEXT,
    product TEXT, version TEXT, state TEXT NOT NULL,
    UNIQUE(asset_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    change_type TEXT NOT NULL, description TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id);
CREATE INDEX IF NOT EXISTS idx_changes_scan ON changes(scan_id);
"""


def connect_db(settings: Settings) -> sqlite3.Connection:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(settings: Settings) -> None:
    with connect_db(settings) as db:
        db.executescript(SCHEMA)


def parse_nmap_xml(xml_data: str) -> list[dict[str, Any]]:
    """Convert Nmap XML into scanner-neutral asset dictionaries."""
    root = ET.fromstring(xml_data)
    devices = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addresses = host.findall("address")
        ip = next((a.get("addr") for a in addresses if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not ip:
            continue
        hostname_node = host.find("./hostnames/hostname")
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append({
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "state": state.get("state", "open"),
                "service_name": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
            })
        mac = next((a for a in addresses if a.get("addrtype") == "mac"), None)
        devices.append({
            "ip_address": ip,
            "hostname": hostname_node.get("name") if hostname_node is not None else None,
            "mac_address": mac.get("addr") if mac is not None else None,
            "vendor": mac.get("vendor") if mac is not None else None,
            "services": services,
        })
    return devices


class NmapScanner:
    def __init__(self, settings: Settings):
        self.settings = settings

    def scan(self, target: str) -> list[dict[str, Any]]:
        network = self.settings.authorize_target(target)
        command = [
            self.settings.nmap_path, "-oX", "-", "-sV", "--top-ports", "100",
            "-T4", str(network),
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=300, check=False, shell=False
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Nmap is not installed or NMAP_PATH is incorrect") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Nmap scan timed out after 300 seconds") from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or "Nmap returned a non-zero exit code"
            raise RuntimeError(detail[:500])
        try:
            return parse_nmap_xml(result.stdout)
        except ET.ParseError as exc:
            raise RuntimeError("Nmap returned invalid XML") from exc


def record_scan(settings: Settings, scanner: NmapScanner, target: str) -> int:
    started = utc_now()
    with connect_db(settings) as db:
        cursor = db.execute(
            "INSERT INTO scans(target, started_at, status) VALUES (?, ?, 'running')",
            (target, started),
        )
        scan_id = cursor.lastrowid
    try:
        devices = scanner.scan(target)
        completed = utc_now()
        with connect_db(settings) as db:
            previously_seen = {
                row["ip_address"] for row in db.execute("SELECT ip_address FROM assets WHERE status='up'")
            }
            db.execute("UPDATE assets SET status='down' WHERE status='up'")
            for device in devices:
                old = db.execute(
                    "SELECT * FROM assets WHERE ip_address = ?", (device["ip_address"],)
                ).fetchone()
                db.execute(
                    """INSERT INTO assets(ip_address, hostname, mac_address, vendor, last_seen, status)
                       VALUES (?, ?, ?, ?, ?, 'up')
                       ON CONFLICT(ip_address) DO UPDATE SET hostname=excluded.hostname,
                       mac_address=excluded.mac_address, vendor=excluded.vendor,
                       last_seen=excluded.last_seen, status='up'""",
                    (device["ip_address"], device["hostname"], device["mac_address"],
                     device["vendor"], completed),
                )
                asset_id = db.execute(
                    "SELECT id FROM assets WHERE ip_address = ?", (device["ip_address"],)
                ).fetchone()["id"]
                previous = {
                    (row["port"], row["protocol"]): row
                    for row in db.execute(
                        "SELECT * FROM services WHERE asset_id = ?", (asset_id,)
                    )
                }
                current = {(s["port"], s["protocol"]): s for s in device["services"]}
                if old is None:
                    db.execute(
                        "INSERT INTO changes(scan_id, asset_id, change_type, description, created_at)"
                        " VALUES (?, ?, 'new_device', ?, ?)",
                        (scan_id, asset_id, f"New device discovered: {device['ip_address']}", completed),
                    )
                for key, service in current.items():
                    if key not in previous:
                        description = f"Open service added on {device['ip_address']}: {key[0]}/{key[1]}"
                        db.execute("INSERT INTO changes(scan_id, asset_id, change_type, description, created_at)"
                                   " VALUES (?, ?, 'service_added', ?, ?)",
                                   (scan_id, asset_id, description, completed))
                    elif any(service[field] != previous[key][field]
                             for field in ("service_name", "product", "version")):
                        description = f"Service identification changed on {device['ip_address']}: {key[0]}/{key[1]}"
                        db.execute("INSERT INTO changes(scan_id, asset_id, change_type, description, created_at)"
                                   " VALUES (?, ?, 'service_changed', ?, ?)",
                                   (scan_id, asset_id, description, completed))
                for key in previous.keys() - current.keys():
                    description = f"Service removed from {device['ip_address']}: {key[0]}/{key[1]}"
                    db.execute("INSERT INTO changes(scan_id, asset_id, change_type, description, created_at)"
                               " VALUES (?, ?, 'service_removed', ?, ?)",
                               (scan_id, asset_id, description, completed))
                db.execute("DELETE FROM services WHERE asset_id = ?", (asset_id,))
                db.executemany(
                    """INSERT INTO services(asset_id, port, protocol, service_name, product, version, state)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    [(asset_id, s["port"], s["protocol"], s["service_name"], s["product"],
                      s["version"], s["state"]) for s in device["services"]],
                )
            for missing_ip in previously_seen - {device["ip_address"] for device in devices}:
                missing_id = db.execute(
                    "SELECT id FROM assets WHERE ip_address = ?", (missing_ip,)
                ).fetchone()["id"]
                db.execute("INSERT INTO changes(scan_id, asset_id, change_type, description, created_at)"
                           " VALUES (?, ?, 'device_down', ?, ?)",
                           (scan_id, missing_id, f"Device no longer responding: {missing_ip}", completed))
            db.execute(
                "UPDATE scans SET completed_at=?, status='completed', devices_found=? WHERE id=?",
                (completed, len(devices), scan_id),
            )
        return scan_id
    except Exception as exc:
        with connect_db(settings) as db:
            db.execute("UPDATE scans SET completed_at=?, status='failed', error=? WHERE id=?",
                       (utc_now(), str(exc)[:500], scan_id))
        raise


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_environment()
    init_db(settings)
    app = Flask(__name__)
    app.config["SETTINGS"] = settings
    scanner = NmapScanner(settings)
    scan_lock = threading.Lock()
    scan_state = {"running": False, "last_error": None}

    def authorized(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            supplied = request.headers.get("X-API-Key", "")
            if not supplied or not secrets.compare_digest(supplied, settings.api_key):
                return jsonify(error="Authentication required"), 401
            return view(*args, **kwargs)
        return wrapper

    def run_scan(target: str) -> None:
        with scan_lock:
            scan_state["running"] = True
            scan_state["last_error"] = None
            try:
                record_scan(settings, scanner, target)
            except Exception as exc:
                scan_state["last_error"] = str(exc)
            finally:
                scan_state["running"] = False

    def scheduler() -> None:
        while True:
            time.sleep(settings.scan_interval_seconds)
            if not scan_state["running"]:
                for network in settings.allowed_networks:
                    if not scan_state["running"]:
                        run_scan(str(network))

    if settings.scan_interval_seconds > 0:
        threading.Thread(target=scheduler, name="inventory-scheduler", daemon=True).start()

    @app.get("/")
    def dashboard() -> str:
        return render_template("index.html")

    @app.get("/api/status")
    @authorized
    def status() -> Any:
        with connect_db(settings) as db:
            scan = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            return jsonify(running=scan_state["running"], last_error=scan_state["last_error"],
                           last_scan=dict(scan) if scan else None)

    @app.get("/api/assets")
    @authorized
    def assets() -> Any:
        query = request.args.get("q", "").strip()
        service = request.args.get("service", "").strip()
        with connect_db(settings) as db:
            rows = db.execute(
                """SELECT a.*, GROUP_CONCAT(s.port || '/' || s.protocol || ':' ||
                   COALESCE(s.service_name, 'unknown'), ', ') services
                   FROM assets a LEFT JOIN services s ON s.asset_id=a.id
                   WHERE (a.ip_address LIKE ? OR COALESCE(a.hostname,'') LIKE ?)
                   GROUP BY a.id ORDER BY a.ip_address""",
                (f"%{query}%", f"%{query}%"),
            ).fetchall()
            values = [dict(row) for row in rows]
            if service:
                values = [row for row in values if service.lower() in (row["services"] or "").lower()]
            return jsonify(assets=values)

    @app.get("/api/changes")
    @authorized
    def changes() -> Any:
        with connect_db(settings) as db:
            rows = db.execute(
                "SELECT c.*, a.ip_address FROM changes c LEFT JOIN assets a ON a.id=c.asset_id"
                " ORDER BY c.id DESC LIMIT 100"
            ).fetchall()
            return jsonify(changes=[dict(row) for row in rows])

    @app.get("/api/scans")
    @authorized
    def scans() -> Any:
        with connect_db(settings) as db:
            rows = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()
            return jsonify(scans=[dict(row) for row in rows])

    @app.post("/api/scans")
    @authorized
    def start_scan() -> Any:
        if scan_state["running"]:
            return jsonify(error="A scan is already running"), 409
        payload = request.get_json(silent=True) or {}
        target = str(payload.get("target", "")).strip()
        try:
            settings.authorize_target(target)
        except (ValueError, PermissionError) as exc:
            return jsonify(error=str(exc)), 400
        thread = threading.Thread(target=run_scan, args=(target,), daemon=True)
        thread.start()
        return jsonify(message="Scan started", target=target), 202

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
