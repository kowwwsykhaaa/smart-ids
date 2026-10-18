"""Anomaly detection with Isolation Forest.

Idea: describe each source IP's behaviour in a short time window with a handful
of numbers (features). Train Isolation Forest on NORMAL traffic only. At run time,
windows that look unlike anything seen in training are flagged as anomalies.

Unlike the rules, this can flag attack shapes nobody wrote a rule for (for
example a SYN flood), at the price of some false alarms.
"""
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

from .packets import Pkt
from .detector import Alert

WINDOW = 10  # seconds
FEATURES = ["packets", "syn_packets", "unique_dports", "unique_dsts",
            "icmp_packets", "udp_packets", "mean_len", "syn_ratio"]


def window_features(pkts):
    """Turn the packets of ONE source in ONE window into a feature vector."""
    n = len(pkts)
    syn = sum(1 for p in pkts if p.proto == "TCP" and p.flags == "S")
    return [
        n,
        syn,
        len({p.dport for p in pkts if p.proto != "ICMP"}),
        len({p.dst for p in pkts}),
        sum(1 for p in pkts if p.proto == "ICMP"),
        sum(1 for p in pkts if p.proto == "UDP"),
        float(np.mean([p.length for p in pkts])),
        syn / n,
    ]


def group_windows(pkts, window=WINDOW):
    """Group packets into {(source_ip, window_index): [packets]}."""
    groups = defaultdict(list)
    for p in pkts:
        groups[(p.src, int(p.ts // window))].append(p)
    return groups


class AnomalyModel:
    def __init__(self, n_estimators=200, contamination=0.01, seed=42):
        self.model = IsolationForest(n_estimators=n_estimators,
                                     contamination=contamination,
                                     random_state=seed)

    def fit(self, benign_pkts):
        groups = group_windows(benign_pkts)
        X = np.array([window_features(v) for v in groups.values()])
        self.model.fit(X)
        return len(X)

    def predict_windows(self, pkts):
        """Return {(src, window_idx): True if anomalous}."""
        groups = group_windows(pkts)
        keys = list(groups)
        X = np.array([window_features(groups[k]) for k in keys])
        pred = self.model.predict(X)          # -1 = anomaly, 1 = normal
        return {k: bool(v == -1) for k, v in zip(keys, pred)}


class StreamingAnomalyDetector:
    """Live use: buffer packets per source; when a window closes, score it."""

    def __init__(self, model: AnomalyModel, window=WINDOW):
        self.model, self.window = model, window
        self._buf = defaultdict(list)       # (src, idx) -> packets
        self._current = None

    def process(self, p: Pkt):
        idx = int(p.ts // self.window)
        out = []
        if self._current is not None and idx > self._current:
            out = self._flush(before=idx)
        self._current = idx
        self._buf[(p.src, idx)].append(p)
        return out

    def _flush(self, before):
        alerts, done = [], [k for k in self._buf if k[1] < before]
        for k in done:
            pkts = self._buf.pop(k)
            x = np.array([window_features(pkts)])
            if self.model.model.predict(x)[0] == -1:
                alerts.append(Alert(pkts[-1].ts, k[0], "Anomalous Traffic",
                                    "Medium", 0, pkts[-1].proto, source="ml"))
        return alerts
