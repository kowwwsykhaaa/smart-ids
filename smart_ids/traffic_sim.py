"""Synthetic labeled traffic for testing the detectors.

IMPORTANT: this generates packet RECORDS in memory. It sends nothing on any
network. Results measured on it show how the detectors behave on traffic with
the shapes defined below; they are NOT a claim about real-world accuracy.

Attack episodes deliberately include slow/weak variants (below the rule
thresholds) and one attack type (SYN flood) that no rule covers, so the
evaluation shows real misses instead of a perfect score.
"""
import random

from .packets import Pkt

TARGET = "10.0.0.5"


def _benign(rng, duration, n_clients=40):
    pkts = []
    clients = [f"10.0.{rng.randint(1, 9)}.{rng.randint(10, 250)}" for _ in range(n_clients)]
    for c in clients:
        t = rng.uniform(0, 20)
        heavy = rng.random() < 0.1      # some clients download big files
        dev = rng.random() < 0.05       # some open many connections (developers)
        while t < duration:
            t += rng.expovariate(1 / 25)             # a session every ~25 s
            dst = f"93.184.{rng.randint(0, 5)}.{rng.randint(1, 250)}"
            port = rng.choice([443, 443, 443, 80, 80, 8080, 8443])
            pkts.append(Pkt(t, c, dst, "TCP", port, "S", 60))
            n = rng.randint(80, 300) if heavy and rng.random() < 0.3 else rng.randint(4, 40)
            for i in range(n):
                pkts.append(Pkt(t + 0.01 * (i + 1), c, dst, "TCP", port, "A",
                                rng.choice([60, 576, 1400, 1400])))
            if rng.random() < 0.3:                   # DNS lookup
                pkts.append(Pkt(t, c, "8.8.8.8", "UDP", 53, "", rng.randint(60, 90)))
            if rng.random() < 0.02:                  # occasional ping
                for i in range(rng.randint(1, 4)):
                    pkts.append(Pkt(t + i, c, dst, "ICMP", 0, "", 84))
            if rng.random() < 0.01:                  # legit SSH login
                for i in range(rng.randint(1, 2)):
                    pkts.append(Pkt(t + i, c, TARGET, "TCP", 22, "S", 60))
            if dev and rng.random() < 0.2:           # burst of parallel connections
                for i in range(rng.randint(10, 25)):
                    d2 = f"151.101.{rng.randint(0, 5)}.{rng.randint(1, 250)}"
                    pkts.append(Pkt(t + 0.05 * i, c, d2, "TCP", 443, "S", 60))
    return pkts


def _attack(rng, kind, start, src):
    """Return (packets, end_time) for one attack episode."""
    pkts, t = [], start
    if kind == "ssh_bruteforce":
        rate = rng.choice([0.05, 0.08, 0.3, 0.5, 1.0, 2.0])      # attempts per second
        for _ in range(rng.randint(8, 80)):
            t += rng.expovariate(rate)
            pkts.append(Pkt(t, src, TARGET, "TCP", 22, "S", 60))
            for i in range(3):
                pkts.append(Pkt(t + 0.05 * (i + 1), src, TARGET, "TCP", 22, "A", 100))
    elif kind == "port_scan":
        rate = rng.choice([0.2, 0.3, 1.0, 5.0, 20.0])            # ports per second
        for port in rng.sample(range(1, 1024), rng.randint(20, 200)):
            t += rng.expovariate(rate)
            pkts.append(Pkt(t, src, TARGET, "TCP", port, "S", 60))
    elif kind == "icmp_flood":
        rate = rng.choice([4.0, 8.0, 30.0, 100.0, 300.0])        # packets per second
        for _ in range(int(rate * rng.randint(10, 40))):
            t += rng.expovariate(rate)
            pkts.append(Pkt(t, src, TARGET, "ICMP", 0, "", rng.choice([84, 1000, 1400])))
    elif kind == "syn_flood":                                    # no rule covers this one
        rate = rng.choice([50.0, 100.0, 300.0, 500.0])
        for _ in range(int(rate * rng.randint(10, 30))):
            t += rng.expovariate(rate)
            pkts.append(Pkt(t, src, TARGET, "TCP", rng.choice([80, 443]), "S", 60))
    return pkts, t


ATTACK_KINDS = ["ssh_bruteforce", "port_scan", "icmp_flood", "syn_flood"]


def generate(seed, duration=3600, n_episodes=0):
    """Returns (packets_sorted, episodes). Each episode = dict(kind, src, start, end)."""
    rng = random.Random(seed)
    pkts = _benign(rng, duration)
    episodes = []
    for i in range(n_episodes):
        kind = ATTACK_KINDS[i % len(ATTACK_KINDS)]
        src = f"203.0.113.{(i % 250) + 1}"
        start = rng.uniform(30, duration - 400)
        ap, end = _attack(rng, kind, start, src)
        pkts += ap
        episodes.append(dict(kind=kind, src=src, start=start, end=end))
    pkts.sort(key=lambda p: p.ts)
    return pkts, episodes
