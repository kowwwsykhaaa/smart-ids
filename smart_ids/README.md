# Smart IDS

A small network intrusion detection system in Python. It watches packets, flags suspicious behaviour with
**rules** and an **Isolation Forest** model, shows alerts on a web dashboard, and can (optionally) block
attackers with firewall rules.

## What it detects

| Detector | What it looks for |
|---|---|
| Rule: SSH Brute Force | 6+ SYN packets to port 22 from one IP within 60 s |
| Rule: Port Scan | SYNs to 15+ different ports from one IP within 30 s |
| Rule: ICMP Flood | 100+ ICMP packets from one IP within 10 s |
| Isolation Forest | Any 10-second window of one IP's traffic that looks unlike normal traffic (8 features: packets, SYNs, distinct ports/hosts, ICMP/UDP counts, mean size, SYN ratio) |

## Run it

```bash
pip install -r smart_ids/requirements.txt   # run all commands from the folder that CONTAINS smart_ids/
python -m smart_ids.run                      # safe replay demo, no admin needed
python -m smart_ids.run --mode live          # real capture (admin + Npcap on Windows, root on Linux)
python -m smart_ids.run --mode live --enforce   # also adds real firewall block rules
python -m smart_ids.evaluate                 # re-measure detectors, rewrites results.md
python -m pytest smart_ids/tests             # 13 tests
```

Replay mode feeds recorded **synthetic** traffic through the real detection code. Nothing touches the network.

## Safety
- Blocking is **dry-run by default**. `--enforce` is required to add firewall rules.
- Only public IPs can be blocked, never private, loopback or documentation ranges.
- IPs are validated and passed to the firewall command as arguments (no shell).
- The server listens on 127.0.0.1 only.

## Results (synthetic traffic)

Measured by `evaluate.py` on generated labeled traffic (317k packets, 80 attack episodes, 4,970 benign
source-windows). Attacks include slow and weak variants and a SYN flood that no rule covers.

| Detector | Episode recall | Alert precision | F1 | False alarms |
|---|---|---|---|---|
| Rules only | 56% | 100% | 0.72 | 0 |
| Isolation Forest only | 71% | 91% | 0.80 | 24 |
| Rules + Isolation Forest | 91% | 93% | 0.92 | 24 |

Full per-attack breakdown: `results.md`.

## Scope and next steps

**Evaluation.** Results above are measured on synthetic labeled traffic, so they show how the detectors
behave on known attack shapes, not real-world accuracy. Next: evaluate on CIC-IDS2017.

**Detection coverage.** Three rules (SSH brute force, port scan, ICMP flood) plus an Isolation Forest for
unseen patterns. Slow attacks below the rule thresholds are handled by the model or missed; both are
visible in results.md. Payload-level attacks (DNS tunneling, C2 beaconing) are out of scope for now.

**Deployment.** Live capture is implemented and its packet parsing is unit-tested; the model is trained
on synthetic normal traffic and should be retrained on the target network's own traffic.

## Layout
`packets.py` packet record · `detector.py` rules · `ml.py` Isolation Forest · `netcapture.py` Scapy adapter ·
`responder.py` safe blocking · `server.py` API · `traffic_sim.py` + `evaluate.py` testing · `dashboard.html` UI
