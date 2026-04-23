#!/usr/bin/env python3
"""
Console Alerter - Real-time console alerts for suspicious events.
"""

import sys
from typing import Optional, List, Dict
from datetime import datetime


try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich import box
except ImportError:
    Console = None
    Table = None
    Live = None
    Panel = None
    Layout = None
    box = None


SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow", 
    "low": "green",
    "info": "blue"
}


class ConsoleAlerter:
    """Alerts to console in real-time."""
    
    def __init__(
        self,
        console: Optional[Console] = None,
        show_all: bool = False,
        severity_threshold: str = "low",
        max_alerts: int = 50
    ):
        self.console = console or Console()
        self.show_all = show_all
        self.severity_threshold = severity_threshold
        self.max_alerts = max_alerts
        self.alerts: List[Dict] = []
        
        self._severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    
    def alert(
        self,
        message: str,
        severity: str = "info",
        source_ip: str = "",
        user: str = "",
        timestamp: str = "",
        **kwargs
    ) -> None:
        """Send an alert to console."""
        if not self._should_alert(severity):
            return
        
        alert = {
            "timestamp": timestamp or datetime.now().strftime("%b %d %H:%M:%S"),
            "severity": severity.upper(),
            "source_ip": source_ip,
            "user": user,
            "message": message[:100]
        }
        
        self.alerts.append(alert)
        
        # Keep max alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
        
        # Print to console
        self._print_alert(alert)
    
    def _should_alert(self, severity: str) -> bool:
        """Check if severity passes threshold."""
        if self.show_all:
            return True
        
        alert_level = self._severity_order.get(severity.lower(), 4)
        threshold_level = self._severity_order.get(self.severity_threshold, 3)
        
        return alert_level <= threshold_level
    
    def _print_alert(self, alert: Dict) -> None:
        """Print a single alert."""
        severity = alert["severity"].lower()
        color = SEVERITY_COLORS.get(severity, "white")
        
        prefix = f"[{color}]"
        ts = alert["timestamp"]
        src = alert.get("source_ip", "")
        user = alert.get("user", "")
        
        parts = [f"{ts}"]
        if src:
            parts.append(f"src={src}")
        if user:
            parts.append(f"user={user}")
        parts.append(f"[{color}]{alert['message']}[/{color}]")
        
        self.console.print(f"{prefix}[{severity}]{alert['severity']}[/{severity}]{prefix}] " + " | ".join(parts))
    
    def get_alert_summary(self) -> Dict:
        """Get summary of alerts."""
        summary = {"total": len(self.alerts)}
        
        severity_counts = {}
        for alert in self.alerts:
            sev = alert["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        summary.update(severity_counts)
        return summary
    
    def clear(self) -> None:
        """Clear alerts."""
        self.alerts = []


class LiveConsoleAlerter:
    """Live updating console alerter with table."""
    
    def __init__(
        self,
        console: Optional[Console] = None,
        severity_threshold: str = "low"
    ):
        self.console = console or Console()
        self.severity_threshold = severity_threshold
        self.alerts: List[Dict] = []
        
        self._severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self._live = None
    
    def alert(
        self,
        message: str,
        severity: str = "info",
        source_ip: str = "",
        user: str = "",
        timestamp: str = "",
        **kwargs
    ) -> None:
        """Send an alert."""
        if not self._should_alert(severity):
            return
        
        alert = {
            "timestamp": timestamp or datetime.now().strftime("%b %d %H:%M:%S"),
            "severity": severity.upper(),
            "source_ip": source_ip,
            "user": user,
            "message": message[:80]
        }
        
        self.alerts.append(alert)
        
        # Update display
        self._update_display()
    
    def _should_alert(self, severity: str) -> bool:
        """Check if should alert."""
        alert_level = self._severity_order.get(severity.lower(), 4)
        threshold_level = self._severity_order.get(self.severity_threshold, 3)
        return alert_level <= threshold_level
    
    def _update_display(self) -> None:
        """Update live display."""
        if not Table:
            return
        
        table = Table(title="Recent Alerts", box=box.ROUNDED)
        table.add_column("Time", style="cyan")
        table.add_column("Severity", style="white")
        table.add_column("Source IP", style="magenta")
        table.add_column("User", style="green")
        table.add_column("Message", style="white")
        
        for alert in self.alerts[-20:]:
            sev = alert["severity"].lower()
            style = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                alert["timestamp"],
                f"[{style}]{alert['severity']}[/{style}]",
                alert.get("source_ip", "-"),
                alert.get("user", "-"),
                alert["message"]
            )
        
        try:
            if self._live:
                self._live.update(Panel(table))
            else:
                self._live = Live(Panel(table), console=self.console)
                self._live.start()
        except Exception:
            pass
    
    def stop(self) -> None:
        """Stop live display."""
        try:
            if self._live:
                self._live.stop()
        except Exception:
            pass