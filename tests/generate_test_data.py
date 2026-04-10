import json
import random
import time
import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np


def generate_normal_traffic(n=1000):
    rng = np.random.RandomState(42)
    ips = [f"192.168.1.{i}" for i in range(1, 50)] + [f"10.0.0.{i}" for i in range(1, 20)]
    data = []
    for _ in range(n):
        ip = random.choice(ips)
        data.append({
            "ip_address": ip,
            "packet_count": int(rng.poisson(50)),
            "total_bytes": int(rng.exponential(5000)),
            "unique_ports": int(rng.poisson(3)),
            "frequency": round(float(rng.exponential(2)), 4),
            "unique_dst_ips": int(rng.poisson(2)),
            "syn_count": int(rng.poisson(1)),
            "protocols": random.sample(["TCP", "UDP", "ICMP"], k=random.randint(1, 2)),
        })
    return data


def generate_attack_traffic(n=100):
    rng = np.random.RandomState(99)
    attack_ips = [f"10.{rng.randint(1,255)}.{rng.randint(1,255)}.{rng.randint(1,255)}" for _ in range(20)]
    attack_types = [
        {"name": "port_scan", "syn_ratio": 0.9, "unique_ports": (50, 200), "frequency": (50, 200)},
        {"name": "dos_flood", "syn_ratio": 0.95, "packet_count": (500, 5000), "frequency": (100, 500)},
        {"name": "brute_force", "syn_ratio": 0.3, "unique_ports": (1, 3), "frequency": (10, 50)},
        {"name": "data_exfil", "syn_ratio": 0.1, "total_bytes": (50000, 500000), "frequency": (5, 20)},
    ]
    data = []
    for _ in range(n):
        ip = random.choice(attack_ips)
        attack = random.choice(attack_types)
        entry = {
            "ip_address": ip,
            "packet_count": int(rng.poisson(attack.get("packet_count", (100, 1000))[1])),
            "total_bytes": int(rng.exponential(attack.get("total_bytes", (10000, 100000))[1])),
            "unique_ports": random.randint(*attack.get("unique_ports", (5, 50))),
            "frequency": round(random.uniform(*attack.get("frequency", (20, 100))), 4),
            "unique_dst_ips": int(rng.poisson(5)),
            "syn_count": int(rng.poisson(50)),
            "protocols": ["TCP"],
            "attack_type": attack["name"],
        }
        data.append(entry)
    return data


def generate_incidents(n=50):
    levels = ["faible", "moyen", "critique"]
    actions = ["monitored", "blocked", "alert_sent", "blocked (duration: 3600s)"]
    ips = [f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(20)]
    incidents = []
    base_time = datetime.now() - timedelta(hours=24)
    for i in range(n):
        level = random.choices(levels, weights=[0.5, 0.3, 0.2])[0]
        score_map = {"faible": (0.05, 0.3), "moyen": (0.3, 0.7), "critique": (0.7, 1.0)}
        score = round(random.uniform(*score_map[level]), 4)
        incidents.append({
            "id": i + 1,
            "ip_address": random.choice(ips),
            "risk_score": score,
            "risk_level": level,
            "action_taken": random.choice(actions),
            "timestamp": (base_time + timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "packet_count": random.randint(10, 1000),
            "details": {
                "base_score": round(score * 0.5, 4),
                "behavioral_score": round(score * 0.3, 4),
                "vulnerability_score": round(score * 0.2, 4),
                "is_anomaly": level != "faible",
            },
        })
    return incidents


def main():
    print("Generating test datasets...")

    normal = generate_normal_traffic(1000)
    with open("tests/data_normal_traffic.json", "w") as f:
        json.dump(normal, f, indent=2)
    print(f"  Normal traffic: {len(normal)} entries")

    attacks = generate_attack_traffic(100)
    with open("tests/data_attack_traffic.json", "w") as f:
        json.dump(attacks, f, indent=2)
    print(f"  Attack traffic: {len(attacks)} entries")

    incidents = generate_incidents(50)
    with open("tests/data_incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)
    print(f"  Incidents: {len(incidents)} entries")

    combined = {
        "normal_traffic": normal,
        "attack_traffic": attacks,
        "incidents": incidents,
    }
    with open("tests/test_dataset.json", "w") as f:
        json.dump(combined, f, indent=2)

    print("\nTest data generated in tests/ directory")
    print("Files: data_normal_traffic.json, data_attack_traffic.json, data_incidents.json, test_dataset.json")


if __name__ == "__main__":
    main()
