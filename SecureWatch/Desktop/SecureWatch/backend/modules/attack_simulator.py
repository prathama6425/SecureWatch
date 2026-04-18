"""
Attack Simulator
=================
Generates realistic attack log entries to simulate:
  1. Brute force SSH attack (T1110)
  2. Network port scan (T1046)
  3. Phishing + web credential harvesting (T1566)
  4. C2 beacon / lateral movement
  5. Data exfiltration attempt

Uses log_collector to normalize and ingest the simulated logs
so the full detection pipeline fires.
"""

import random
import time
from datetime import datetime, timedelta
from modules.log_collector import ingest_log_batch
from modules.threat_detector import run_detection
from modules.correlator import run_correlation
from modules.threat_intel import match_logs_against_iocs

# ── Attacker IPs (some are in the IOC feed) ───────────────────────────────────
ATTACKER_IPS = [
    "45.142.212.100",   # In IOC feed (malicious)
    "185.220.101.45",   # In IOC feed (Tor exit node)
    "192.168.99.200",   # Internal rogue device
    "103.25.206.34",    # Generic external
    "198.51.100.77",    # Documentation range (safe-looking)
]

TARGET_IPS   = ["10.0.0.10", "10.0.0.20", "10.0.0.30"]
USERNAMES    = ["root", "admin", "ubuntu", "ec2-user", "deploy", "git"]
SERVICES     = ["sshd", "vsftpd", "postfix", "apache2"]


def _ts(offset_secs: int = 0) -> str:
    """Return a timestamp offset from now (negative = past)."""
    t = datetime.now() + timedelta(seconds=offset_secs)
    return t.strftime("%Y-%m-%d %H:%M:%S")


# ── Simulation 1: SSH Brute Force ────────────────────────────────────────────

def sim_brute_force(attacker_ip: str = None, target_user: str = "root",
                    num_attempts: int = 20) -> dict:
    """
    Simulate a brute-force SSH attack:
    N failed attempts followed by 1 success from the same IP.
    """
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    lines = []
    for i in range(num_attempts):
        lines.append(
            f"Apr 15 {datetime.now().strftime('%H:%M:%S')} "
            f"victim-srv sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {target_user} from {ip} port {random.randint(40000,65000)} ssh2"
        )
    # Final success
    lines.append(
        f"Apr 15 {datetime.now().strftime('%H:%M:%S')} "
        f"victim-srv sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {target_user} from {ip} port {random.randint(40000,65000)} ssh2"
    )

    logs = ingest_log_batch(lines, "linux")
    alerts = run_detection(logs)
    alerts += run_correlation(logs)
    alerts += match_logs_against_iocs(logs)

    return {
        "simulation": "brute_force",
        "attacker_ip": ip,
        "target_user": target_user,
        "attempts": num_attempts + 1,
        "logs_ingested": len(logs),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


# ── Simulation 2: Port Scan ───────────────────────────────────────────────────

def sim_port_scan(attacker_ip: str = None, num_ports: int = 30) -> dict:
    """
    Simulate a TCP port scan generating firewall BLOCK entries
    for many distinct destination ports.
    """
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    target = random.choice(TARGET_IPS)
    ports = random.sample(range(1, 65536), num_ports)
    lines = []
    for port in ports:
        lines.append(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"BLOCK TCP {ip}:{random.randint(40000,65000)} -> {target}:{port} "
            f"(rule: tcp-portscan-block)"
        )

    logs = ingest_log_batch(lines, "firewall")
    alerts = run_detection(logs)
    alerts += run_correlation(logs)
    alerts += match_logs_against_iocs(logs)

    return {
        "simulation": "port_scan",
        "attacker_ip": ip,
        "target_ip": target,
        "ports_scanned": num_ports,
        "logs_ingested": len(logs),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


# ── Simulation 3: Phishing Web Attack ────────────────────────────────────────

def sim_phishing_web(attacker_ip: str = None) -> dict:
    """
    Simulate a phishing scenario:
    - Attacker accesses fake login page → credential harvest
    - Multiple 401s on /admin panel
    - Eventual successful /login POST
    """
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    lines = [
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"GET /phishing-login.html HTTP/1.1" 200 4321',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"POST /login HTTP/1.1" 401 0',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"POST /login HTTP/1.1" 401 0',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"POST /login HTTP/1.1" 401 0',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"POST /login HTTP/1.1" 401 0',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"POST /login HTTP/1.1" 401 0',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"GET /admin HTTP/1.1" 403 512',
        f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"GET /.env HTTP/1.1" 200 88',
    ]

    logs = ingest_log_batch(lines, "web")
    alerts = run_detection(logs)
    alerts += run_correlation(logs)
    alerts += match_logs_against_iocs(logs)

    return {
        "simulation": "phishing_web",
        "attacker_ip": ip,
        "scenario": "Phishing + Admin Panel Probe + .env Exposure",
        "logs_ingested": len(logs),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


# ── Simulation 4: Full Attack Chain ──────────────────────────────────────────

def sim_full_chain(attacker_ip: str = None) -> dict:
    """
    Full attack chain: Port scan → Brute force → Successful login → Web recon.
    Demonstrates cross-correlation firing.
    """
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    scan = sim_port_scan(ip, 20)
    bf   = sim_brute_force(ip, "admin", 10)
    web  = sim_phishing_web(ip)

    return {
        "simulation": "full_chain",
        "attacker_ip": ip,
        "stages": ["port_scan", "brute_force", "phishing_web"],
        "total_logs": scan["logs_ingested"] + bf["logs_ingested"] + web["logs_ingested"],
        "total_alerts": scan["alerts_generated"] + bf["alerts_generated"] + web["alerts_generated"],
        "stage_results": {
            "port_scan":    scan,
            "brute_force":  bf,
            "phishing_web": web,
        },
    }


# ── Registry ──────────────────────────────────────────────────────────────────

SIMULATIONS = {
    "brute_force":  sim_brute_force,
    "port_scan":    sim_port_scan,
    "phishing_web": sim_phishing_web,
    "full_chain":   sim_full_chain,
}


def run_simulation(sim_type: str, attacker_ip: str = None) -> dict:
    """Dispatch to the appropriate simulation."""
    fn = SIMULATIONS.get(sim_type)
    if not fn:
        raise ValueError(f"Unknown simulation '{sim_type}'. "
                         f"Available: {list(SIMULATIONS.keys())}")
    return fn(attacker_ip)
