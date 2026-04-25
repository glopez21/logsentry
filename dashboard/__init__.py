#!/usr/bin/env python3
"""Dashboard module with ASCII visualization and attack chain graphs."""

from collections import defaultdict
from datetime import datetime


def horizontal_bar(value: int, max_value: int, width: int = 40, char: str = "█") -> str:
    """Create horizontal bar chart."""
    if max_value == 0:
        return char * 0
    filled = int((value / max_value) * width)
    return char * filled + "░" * (width - filled)


def sparkline(values: list[int], width: int = 50) -> str:
    """Create ASCII sparkline."""
    if not values:
        return ""
    
    if len(values) > width:
        step = len(values) / width
        values = [values[int(i * step)] for i in range(width)]
    
    min_val, max_val = min(values), max(values)
    range_val = max_val - min_val if max_val != min_val else 1
    
    chars = " ▁▂▃▄▅▆▇█"
    result = []
    for v in values:
        normalized = int(((v - min_val) / range_val) * (len(chars) - 1))
        result.append(chars[normalized])
    
    return "".join(result)


def event_timeline_chart(records: list[dict], width: int = 60) -> str:
    """Create event timeline chart showing activity over time."""
    if not records:
        return "No data"
    
    hour_events = defaultdict(int)
    for r in records:
        ts = r.get("timestamp", "")
        if ts:
            try:
                parts = ts.split()
                time_part = parts[-1] if parts else "00:00:00"
                hour = int(time_part.split(":")[0])
                hour_events[hour] += 1
            except (ValueError, IndexError):
                pass
    
    if not hour_events:
        return "No timestamp data"
    
    chart = "\nEvent Timeline (Events per Hour)\n" + "=" * (width + 20) + "\n"
    
    for hour in range(24):
        count = hour_events.get(hour, 0)
        bar = horizontal_bar(count, max(hour_events.values()), width)
        hour_str = f"{hour:02d}:00"
        chart += f"{hour_str} │{bar}│ {count}\n"
    
    return chart


def severity_distribution(records: list[dict], width: int = 40) -> str:
    """Show severity distribution as stacked bar."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for r in records:
        sev = r.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    total = sum(severity_counts.values())
    if total == 0:
        return "No severity data"
    
    colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
    
    chart = "\nSeverity Distribution\n" + "=" * 50 + "\n"
    
    for sev, count in severity_counts.items():
        pct = (count / total) * 100
        bar = horizontal_bar(count, total, width)
        chart += f"{colors[sev]} {sev.upper():8} │{bar}│ {count:4} ({pct:5.1f}%)\n"
    
    return chart


def top_attackers(records: list[dict], limit: int = 10) -> str:
    """Show top attacking IPs."""
    ip_counts = defaultdict(int)
    for r in records:
        if ip := r.get("source_ip"):
            ip_counts[ip] += 1
    
    if not ip_counts:
        return "No IP data"
    
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:limit]
    max_count = top_ips[0][1] if top_ips else 1
    
    chart = "\nTop Attacking IPs\n" + "=" * 50 + "\n"
    for ip, count in top_ips:
        bar = horizontal_bar(count, max_count, 30)
        chart += f"{ip:15} │{bar}│ {count}\n"
    
    return chart


def top_users(records: list[dict], limit: int = 10) -> str:
    """Show most targeted users."""
    user_counts = defaultdict(int)
    for r in records:
        if user := r.get("user"):
            user_counts[user] += 1
    
    if not user_counts:
        return "No user data"
    
    top_users_list = sorted(user_counts.items(), key=lambda x: -x[1])[:limit]
    max_count = top_users_list[0][1] if top_users_list else 1
    
    chart = "\nMost Targeted Users\n" + "=" * 50 + "\n"
    for user, count in top_users_list:
        bar = horizontal_bar(count, max_count, 30)
        chart += f"{user:15} │{bar}│ {count}\n"
    
    return chart


def event_type_breakdown(records: list[dict]) -> str:
    """Show breakdown by event type."""
    type_counts = defaultdict(int)
    for r in records:
        if et := r.get("event_type"):
            type_counts[et] += 1
    
    if not type_counts:
        return "No event type data"
    
    sorted_types = sorted(type_counts.items(), key=lambda x: -x[1])
    max_count = sorted_types[0][1] if sorted_types else 1
    
    chart = "\nEvent Type Breakdown\n" + "=" * 50 + "\n"
    for et, count in sorted_types[:15]:
        bar = horizontal_bar(count, max_count, 30)
        chart += f"{et[:20]:20} │{bar}│ {count}\n"
    
    return chart


def attack_chain_viz(records: list[dict]) -> str:
    """Visualize attack chain progression."""
    phases = {
        "recon": [],
        "initial_access": [],
        "execution": [],
        "persistence": [],
        "privilege_escalation": [],
        "lateral_movement": [],
        "exfiltration": []
    }
    
    phase_keywords = {
        "recon": ["scan", "recon", "nmap", "ping"],
        "initial_access": ["login", "auth", "accept"],
        "execution": ["exec", "run", "command"],
        "persistence": ["adduser", "new account", "cron", "authorized_keys"],
        "privilege_escalation": ["sudo", "su ", "root", "privilege"],
        "lateral_movement": ["smb", "rdp", "winrm", "ssh"],
        "exfiltration": ["exfil", "upload", "download", "scp"]
    }
    
    for r in records:
        msg = (r.get("raw_message", "") + r.get("message", "")).lower()
        event_type = r.get("event_type", "").lower()
        
        for phase, keywords in phase_keywords.items():
            if any(k in msg or k in event_type for k in keywords):
                phases[phase].append(r)
    
    active_phases = [p for p, records_list in phases.items() if records_list]
    
    if not active_phases:
        return "No attack chain detected"
    
    viz = "\nAttack Chain Visualization\n" + "=" * 50 + "\n"
    viz += "┌" + "─" * 15 + "┬" + "─" * 15 + "┬" + "─" * 15 + "┐\n"
    viz += "│ " + "RECON".ljust(13) + " │ " + "INITIAL".ljust(13) + " │ " + "EXEC".ljust(13) + " │\n"
    viz += "├" + "─" * 15 + "┼" + "─" * 15 + "┼" + "─" * 15 + "┤\n"
    
    for i, phase in enumerate(active_phases[:3]):
        count = len(phases[phase])
        viz += f"│ {phase.upper()[:13].ljust(13)} │"
        if i == 0:
            viz += f" {'✓' if 'initial_access' in active_phases else '·':13} │"
        else:
            viz += " " * 14 + "│"
        viz += " " * 14 + "│\n"
    
    viz += "└" + "─" * 15 + "┴" + "─" * 15 + "┴" + "─" * 15 + "┘\n"
    
    viz += "\nDetected Phases:\n"
    for phase in active_phases:
        count = len(phases[phase])
        viz += f"  ✓ {phase.replace('_', ' ').title()}: {count} events\n"
    
    return viz


def geolocation_map(records: list[dict]) -> str:
    """Show geographic distribution (simplified)."""
    country_counts = defaultdict(int)
    
    tor_prefixes = ("185.220.", "91.121.")
    for r in records:
        if ip := r.get("source_ip"):
            if ip.startswith(tor_prefixes):
                country_counts["Tor Exit"] += 1
            elif ip.startswith("45."):
                country_counts["US"] += 1
            elif ip.startswith("103."):
                country_counts["Asia"] += 1
            else:
                country_counts["Other"] += 1
    
    if not country_counts:
        return "No geographic data"
    
    chart = "\nGeographic Distribution\n" + "=" * 50 + "\n"
    max_count = max(country_counts.values()) if country_counts else 1
    
    for loc, count in sorted(country_counts.items(), key=lambda x: -x[1]):
        bar = horizontal_bar(count, max_count, 30)
        chart += f"{loc:15} │{bar}│ {count}\n"
    
    return chart


def generate_dashboard(records: list[dict]) -> str:
    """Generate full dashboard output."""
    dashboard = """
╔══════════════════════════════════════════════════════════════════╗
║                     LogSentry Security Dashboard                 ║
╚══════════════════════════════════════════════════════════════════╝
"""
    dashboard += f"\nTotal Events: {len(records)}\n"
    
    unique_ips = set(r.get("source_ip") for r in records if r.get("source_ip"))
    unique_users = set(r.get("user") for r in records if r.get("user"))
    dashboard += f"Unique Source IPs: {len(unique_ips)}\n"
    dashboard += f"Unique Users: {len(unique_users)}\n"
    
    dashboard += event_timeline_chart(records)
    dashboard += severity_distribution(records)
    dashboard += top_attackers(records)
    dashboard += top_users(records)
    dashboard += event_type_breakdown(records)
    dashboard += attack_chain_viz(records)
    dashboard += geolocation_map(records)
    
    return dashboard


def print_dashboard(records: list[dict]):
    """Print dashboard to console."""
    print(generate_dashboard(records))