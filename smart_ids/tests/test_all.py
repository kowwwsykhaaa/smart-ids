from fastapi.testclient import TestClient

from smart_ids.packets import Pkt
from smart_ids.detector import RuleDetector
from smart_ids import responder
from smart_ids.netcapture import to_pkt
from smart_ids.server import create_app


def run(det, pkts):
    out = []
    for p in pkts:
        out += det.process(p)
    return out


def syn(t, port, src="1.2.3.4"):
    return Pkt(t, src, "10.0.0.5", "TCP", port, "S", 60)


# ---- rules ----
def test_ssh_brute_force_fires_at_6_syns_in_60s():
    alerts = run(RuleDetector(), [syn(i, 22) for i in range(6)])
    assert [a.attack for a in alerts] == ["Brute Force"]


def test_ssh_five_attempts_do_not_fire():
    assert run(RuleDetector(), [syn(i, 22) for i in range(5)]) == []


def test_ssh_slow_attempts_do_not_fire():
    assert run(RuleDetector(), [syn(i * 20, 22) for i in range(10)]) == []   # 3/min


def test_port_scan_fires_on_15_distinct_ports():
    alerts = run(RuleDetector(), [syn(i * 0.1, 1000 + i) for i in range(15)])
    assert any(a.attack == "Port Scan" for a in alerts)


def test_same_port_repeated_is_not_a_scan():
    assert run(RuleDetector(), [syn(i * 0.1, 443) for i in range(50)]) == []


def test_icmp_flood_threshold():
    ok = [Pkt(i * 0.05, "1.2.3.4", "10.0.0.5", "ICMP", 0, "", 84) for i in range(100)]
    assert run(RuleDetector(), ok) == []
    bad = ok + [Pkt(5.01, "1.2.3.4", "10.0.0.5", "ICMP", 0, "", 84)]
    assert [a.attack for a in run(RuleDetector(), bad)] == ["ICMP Flood"]


def test_cooldown_gives_one_alert_per_attack():
    alerts = run(RuleDetector(), [syn(i * 0.1, 22) for i in range(100)])
    assert len([a for a in alerts if a.attack == "Brute Force"]) == 1


def test_sources_are_tracked_separately():
    pk = [syn(i, 22, src=f"1.2.3.{i % 3}") for i in range(15)]    # 5 SYNs each
    assert run(RuleDetector(), pk) == []


# ---- responder safety ----
def test_only_public_ips_blockable():
    for ip in ["10.0.0.1", "192.168.1.5", "127.0.0.1", "203.0.113.9", "not-an-ip", "8.8.8.8; rm -rf /"]:
        assert not responder.is_blockable(ip)
    assert responder.is_blockable("8.8.8.8")


def test_dry_run_never_calls_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("subprocess must not run in dry-run")
    monkeypatch.setattr(responder.subprocess, "run", boom)
    assert responder.block("8.8.8.8", enforce=False).startswith("dry-run")


def test_private_ip_never_blocked_even_when_enforcing(monkeypatch):
    monkeypatch.setattr(responder.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    assert responder.block("192.168.1.1", enforce=True).startswith("skipped")


# ---- scapy adapter ----
def test_scapy_conversion():
    from scapy.all import IP, TCP, ICMP, UDP
    p = to_pkt(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=22, flags="S"), now=5.0)
    assert (p.proto, p.dport, p.flags, p.src) == ("TCP", 22, "S", "1.1.1.1")
    assert to_pkt(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(), now=1).proto == "ICMP"
    assert to_pkt(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(dport=53), now=1).dport == 53


# ---- API ----
def test_api_events_and_stats():
    app = create_app(mode="replay")
    for i in range(6):                                  # SSH brute force from a public IP
        app.state.on_packet(syn(1000 + i, 22, src="8.8.4.4"))
    c = TestClient(app)
    ev = c.get("/events").json()
    assert ev and ev[0]["attack"] == "Brute Force" and ev[0]["blocked"] is False   # dry-run
    s = c.get("/stats").json()
    assert s["enforcing"] is False and s["critical"] == 1
    assert c.get("/").status_code == 200
    assert c.get("/report").headers["content-type"] == "application/pdf"
