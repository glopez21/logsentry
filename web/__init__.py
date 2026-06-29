"""Web UI for LogSentry — Jinja2 templates and route helpers."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"
_loader = FileSystemLoader(searchpath=str(TEMPLATE_DIR))
_env = Environment(loader=_loader, autoescape=True)


def render_template(name: str, **context: object) -> str:
    """Render a Jinja2 template with context."""
    template = _env.get_template(name)
    return str(template.render(**context))
