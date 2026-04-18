#!/usr/bin/env python3
"""Output formatting utilities."""

from rich.console import Console
from rich.table import Table


console = Console()


def format_output(records: list[dict]) -> None:
    """Format and display records as a table."""
    if not records:
        print("No records to display")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Timestamp", style="dim")
    table.add_column("Host")
    table.add_column("User")
    table.add_column("Source IP")
    table.add_column("Event Type")
    table.add_column("Details")

    for r in records:
        details = r.get("raw_message", "")[:50]
        if len(r.get("raw_message", "")) > 50:
            details += "..."

        table.add_row(
            r.get("timestamp", ""),
            r.get("host", ""),
            r.get("user", ""),
            r.get("source_ip", ""),
            r.get("event_type", ""),
            details
        )

    console.print(table)


def format_triage_summary(checks: dict) -> str:
    """Format triage summary for ticket notes."""
    lines = ["# Triage Summary", ""]

    for check, result in checks.items():
        if isinstance(result, list):
            if result:
                lines.append(f"## {check.replace('_', ' ').title()}")
                for item in result:
                    lines.append(f"- {item}")
                lines.append("")
        elif result:
            lines.append(f"**{check.replace('_', ' ').title()}:** {result}")
            lines.append("")

    return "\n".join(lines)