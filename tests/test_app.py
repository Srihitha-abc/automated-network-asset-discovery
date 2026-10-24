import ipaddress
from pathlib import Path
from unittest.mock import patch

import pytest

from app import NmapScanner, Settings, create_app, parse_nmap_xml


XML = """<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="router"/></hostnames><ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="9"/></port></ports></host></nmaprun>"""


@pytest.fixture
def app(tmp_path: Path):
    settings = Settings(tmp_path / "inventory.db", (ipaddress.ip_network("192.168.1.0/24"),), "a" * 32, 0)
    application = create_app(settings)
    application.config.update(TESTING=True)
    return application


def test_parse_nmap_xml():
    devices = parse_nmap_xml(XML)
    assert devices[0]["hostname"] == "router"
    assert devices[0]["services"][0]["service_name"] == "ssh"


def test_allowlist_rejects_outside_network(app):
    client = app.test_client()
    response = client.post("/api/scans", headers={"X-API-Key": "a" * 32},
                           json={"target": "10.0.0.0/24"})
    assert response.status_code == 400
    assert "outside" in response.json["error"]


def test_scan_persists_assets_and_detects_service_removal(app):
    client = app.test_client()
    with patch.object(NmapScanner, "scan", return_value=parse_nmap_xml(XML)):
        response = client.post("/api/scans", headers={"X-API-Key": "a" * 32},
                               json={"target": "192.168.1.0/24"})
        assert response.status_code == 202
        import time
        for _ in range(100):
            status = client.get("/api/status", headers={"X-API-Key": "a" * 32}).json
            if not status["running"]:
                break
            time.sleep(0.01)
    assets = client.get("/api/assets", headers={"X-API-Key": "a" * 32}).json["assets"]
    assert assets[0]["ip_address"] == "192.168.1.10"


def test_nmap_command_is_argument_list_and_authorized():
    settings = Settings(Path("inventory.db"), (ipaddress.ip_network("192.168.1.0/24"),), "a" * 32, 0)
    scanner = NmapScanner(settings)
    completed = type("Result", (), {"returncode": 0, "stdout": XML, "stderr": ""})()
    with patch("app.subprocess.run", return_value=completed) as run:
        scanner.scan("192.168.1.0/24")
    assert run.call_args.args[0][-1] == "192.168.1.0/24"
    assert run.call_args.kwargs["shell"] is False
