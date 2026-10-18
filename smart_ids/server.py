"""FastAPI backend. Same endpoints the dashboard already uses."""
import asyncio
import io
import queue
import threading
import time
import zlib
from datetime import datetime
from pathlib import Path

import joblib
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

from .detector import RuleDetector, SEVERITY_SCORE
from .ml import AnomalyModel, StreamingAnomalyDetector
from . import responder
from . import traffic_sim

BASE = Path(__file__).parent
UNKNOWN_GEO = {"country": "Unknown", "countryCode": "", "city": "", "lat": 0, "lon": 0}
# Replay mode only: fake attacker IPs have no real location, so the demo map uses fixed
# example cities, clearly labelled "Simulated location". Live mode never invents locations.
DEMO_CITIES = [(55.75, 37.6), (39.9, 116.4), (51.5, -0.1), (48.8, 2.3), (35.6, 139.7),
               (40.7, -74.0), (1.3, 103.8), (-33.8, 151.2), (19.4, -99.1), (-23.5, -46.6)]


def load_model():
    path = BASE / "model.joblib"
    if path.exists():
        return joblib.load(path)
    pkts, _ = traffic_sim.generate(seed=1, duration=3600)       # fallback: train on benign synthetic
    m = AnomalyModel()
    m.fit(pkts)
    return m


def create_app(mode="replay", enforce_blocking=False, use_geo=False):
    app = FastAPI(title="Smart IDS")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
                       allow_methods=["*"], allow_headers=["*"])

    lock = threading.Lock()
    events, blocked, geo_cache = [], {}, {}
    counters = {"packets": 0, "id": 0}
    logq = queue.Queue(maxsize=500)
    email = {"sender": "", "password": "", "receiver": "", "enabled": False}
    alerted = set()

    rules = RuleDetector()
    ml = StreamingAnomalyDetector(load_model())

    def log(msg):
        try:
            logq.put_nowait(f"[{datetime.now():%H:%M:%S}] {msg}")
        except queue.Full:
            pass

    def geo(ip):
        if mode == "replay":
            lat, lon = DEMO_CITIES[zlib.crc32(ip.encode()) % len(DEMO_CITIES)]
            return {"country": "Simulated location", "countryCode": "", "city": "", "lat": lat, "lon": lon}
        if not use_geo or not responder.is_blockable(ip):
            return UNKNOWN_GEO
        if ip not in geo_cache:
            try:
                d = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,lat,lon,city",
                                 timeout=3).json()
                geo_cache[ip] = {k: d.get(k, UNKNOWN_GEO[k]) for k in UNKNOWN_GEO}
            except Exception:
                geo_cache[ip] = UNKNOWN_GEO
        return geo_cache[ip]

    def send_email(ev):
        if not email["enabled"] or ev["ip"] in alerted:
            return
        alerted.add(ev["ip"])
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(f"{ev['severity']} {ev['attack']} from {ev['ip']} at {ev['time']}")
            msg["Subject"] = f"[SMART IDS] {ev['severity']}: {ev['attack']}"
            msg["From"], msg["To"] = email["sender"], email["receiver"]
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(email["sender"], email["password"])
                s.send_message(msg)
            log(f"[ALERT] email sent for {ev['ip']}")
        except Exception as e:
            log(f"[ALERT] email failed: {e}")

    def handle_alert(a):
        g = geo(a.ip)
        with lock:
            counters["id"] += 1
            ev = {"id": counters["id"], "ip": a.ip, "attack": a.attack, "severity": a.severity,
                  "score": SEVERITY_SCORE[a.severity], "protocol": a.protocol, "port": a.port,
                  "blocked": False, "time": datetime.now().strftime("%H:%M:%S"),
                  "source": a.source, **g}
            if a.severity in ("Critical", "High"):
                result = responder.block(a.ip, enforce_blocking)
                log(f"[BLOCK] {a.ip}: {result}")
                if result in ("blocked", "dry-run: block not applied"):
                    blocked[a.ip] = {"reason": a.attack, "time": ev["time"], "applied": result == "blocked"}
                    ev["blocked"] = result == "blocked"
            events.insert(0, ev)
            del events[200:]
        log(f"[EVENT] {a.severity.upper()} {a.attack} from {a.ip} ({a.source})")
        if a.severity in ("Critical", "High"):
            threading.Thread(target=send_email, args=(ev,), daemon=True).start()

    def on_packet(p):
        counters["packets"] += 1
        for a in rules.process(p) + ml.process(p):
            handle_alert(a)

    def replay_loop():
        log("[IDS] REPLAY mode: feeding recorded SYNTHETIC traffic (no real network, no real blocking)")
        pkts, _ = traffic_sim.generate(seed=7, duration=900, n_episodes=12)
        t0, wall0 = pkts[0].ts, time.time()
        speed = 20.0                                   # 20x faster than real time
        for p in pkts:
            delay = (p.ts - t0) / speed - (time.time() - wall0)
            if delay > 0:
                time.sleep(delay)
            on_packet(p)
        log("[IDS] replay finished")

    def start_background():
        if mode == "live":
            from .netcapture import sniff_forever
            log("[IDS] LIVE mode: sniffing real packets" +
                (" (firewall blocking ENABLED)" if enforce_blocking else " (blocking is dry-run)"))
            threading.Thread(target=sniff_forever, args=(on_packet,), daemon=True).start()
        else:
            threading.Thread(target=replay_loop, daemon=True).start()

    app.state.start = start_background
    app.state.on_packet = on_packet
    app.state.events = events

    # ---- routes (same paths the dashboard uses) ----
    @app.get("/events")
    def get_events():
        return events[:100]

    @app.get("/blocked")
    def get_blocked():
        return [{"ip": k, **v} for k, v in blocked.items()]

    @app.get("/stats")
    def stats():
        return {"total": len(events),
                "critical": sum(e["severity"] == "Critical" for e in events),
                "high": sum(e["severity"] == "High" for e in events),
                "blocked": len(blocked), "packet_rate": counters["packets"],
                "mode": mode, "enforcing": enforce_blocking}

    @app.post("/unblock/{ip}")
    def unblock(ip: str):
        if ip not in blocked:
            return {"status": "not found"}
        result = responder.unblock(ip, enforce_blocking)
        del blocked[ip]
        log(f"[UNBLOCK] {ip}: {result}")
        return {"status": "unblocked", "ip": ip}

    @app.post("/email-config")
    def set_email(cfg: dict):
        email.update(sender=cfg.get("sender", ""), password=cfg.get("password", ""),
                     receiver=cfg.get("receiver", ""), enabled=True)
        log(f"[EMAIL] alerts configured for {email['receiver']}")
        return {"status": "ok"}

    @app.get("/email-config")
    def get_email():
        return {"sender": email["sender"], "receiver": email["receiver"], "enabled": email["enabled"]}

    @app.get("/logs")
    async def logs():
        async def gen():
            yield "data: [IDS] Log stream connected\n\n"
            while True:
                try:
                    msg = await asyncio.get_running_loop().run_in_executor(None, lambda: logq.get(timeout=1))
                    yield f"data: {msg}\n\n"
                except Exception:
                    yield ": ping\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post("/start-server")
    def start_server():
        log("[IDS] dashboard connected")
        return {"status": "ok"}

    @app.get("/report")
    def report():
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib import colors
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm)
        st = getSampleStyleSheet()
        rows = [["Time", "Source IP", "Attack", "Severity", "Detector", "Blocked"]]
        rows += [[e["time"], e["ip"], e["attack"], e["severity"], e["source"],
                  "yes" if e["blocked"] else "no"] for e in events[:50]]
        t = Table(rows, repeatRows=1)
        t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.4, colors.black),
                               ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]))
        doc.build([Paragraph("Smart IDS - Incident Report", st["Title"]),
                   Paragraph(f"Generated {datetime.now():%Y-%m-%d %H:%M:%S} | mode: {mode} | "
                             f"events: {len(events)} | IPs blocked: {len(blocked)}", st["Normal"]),
                   Spacer(1, 0.5*cm), t])
        buf.seek(0)
        return StreamingResponse(buf, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=IDS_Report_{datetime.now():%Y%m%d_%H%M%S}.pdf"})

    @app.get("/")
    def root():
        return FileResponse(BASE / "dashboard.html")

    return app