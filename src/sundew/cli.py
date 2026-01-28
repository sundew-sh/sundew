"""Command-line interface for Sundew honeypot."""

from __future__ import annotations

import json
import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from sundew.config import load_config
from sundew.models import AttackClassification
from sundew.persona.generator import generate_persona, save_persona_to_yaml
from sundew.storage import StorageBackend

console = Console()


def _setup_logging(level: str) -> None:
    """Configure logging with the specified level.

    Args:
        level: Logging level string (debug, info, warning, error).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


@click.group()
@click.option("--config", "-c", default=None, help="Path to sundew.yaml config file")
@click.pass_context
def main(ctx: click.Context, config: str | None) -> None:
    """Sundew: An open-source honeypot for detecting AI agent attacks."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    cfg = load_config(config)
    ctx.obj["config"] = cfg
    _setup_logging(cfg.logging.level)


@main.command()
@click.option("--host", default=None, help="Override server host")
@click.option("--port", "-p", default=None, type=int, help="Override server port")
@click.pass_context
def serve(ctx: click.Context, host: str | None, port: int | None) -> None:
    """Start the Sundew honeypot server."""
    import uvicorn

    from sundew.server import create_app

    cfg = ctx.obj["config"]
    server_host = host or cfg.server.host
    server_port = port or cfg.server.port

    console.print(
        f"[bold green]Starting Sundew honeypot on {server_host}:{server_port}[/bold green]"
    )

    app = create_app(ctx.obj["config_path"])
    uvicorn.run(app, host=server_host, port=server_port, log_level=cfg.logging.level)


@main.command()
@click.option(
    "--industry",
    "-i",
    default=None,
    help="Industry theme: fintech, saas, healthcare, etc.",
)
@click.option("--seed", "-s", default=None, type=int, help="Deterministic seed for generation")
@click.option("--output", "-o", default=None, help="Output file path (YAML)")
@click.option("--json-output", is_flag=True, help="Output as JSON instead of YAML")
def generate(
    industry: str | None,
    seed: int | None,
    output: str | None,
    json_output: bool,
) -> None:
    """Generate a new deployment persona."""
    persona = generate_persona(seed=seed)

    if output:
        path = save_persona_to_yaml(persona, output)
        console.print(f"[green]Persona saved to {path}[/green]")
    elif json_output:
        click.echo(persona.model_dump_json(indent=2))
    else:
        table = Table(title=f"Generated Persona: {persona.company_name}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        for key, value in persona.model_dump().items():
            table.add_row(key, str(value))
        console.print(table)


@main.command()
@click.option("--last", "-n", default=10, type=int, help="Number of recent events to show")
@click.option("--classification", "-c", default=None, help="Filter by classification")
@click.option("--sessions", is_flag=True, help="Show sessions instead of events")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.pass_context
def query(
    ctx: click.Context,
    last: int,
    classification: str | None,
    sessions: bool,
    json_output: bool,
) -> None:
    """Query captured honeypot events and sessions."""
    cfg = ctx.obj["config"]
    storage = StorageBackend(db_path=cfg.storage.database)

    if sessions:
        results = storage.get_recent_sessions(limit=last)
        if json_output:
            click.echo(json.dumps([s.model_dump(mode="json") for s in results], indent=2))
        else:
            table = Table(title="Recent Sessions")
            table.add_column("ID", style="dim")
            table.add_column("Source IP", style="cyan")
            table.add_column("Requests", justify="right")
            table.add_column("Classification", style="yellow")
            table.add_column("First Seen")
            table.add_column("Last Seen")
            for s in results:
                table.add_row(
                    s.id[:12],
                    s.source_ip,
                    str(s.request_count),
                    s.classification.value,
                    s.first_seen.isoformat(),
                    s.last_seen.isoformat(),
                )
            console.print(table)
    else:
        if classification:
            cls = AttackClassification(classification)
            events = storage.get_events_by_classification(cls, limit=last)
        else:
            events = storage.get_recent_events(limit=last)

        if json_output:
            click.echo(json.dumps([e.model_dump(mode="json") for e in events], indent=2))
        else:
            table = Table(title="Recent Events")
            table.add_column("Time", style="dim")
            table.add_column("IP", style="cyan")
            table.add_column("Method")
            table.add_column("Path", style="green")
            table.add_column("Status", justify="right")
            table.add_column("Classification", style="yellow")
            table.add_column("Trap")
            for e in events:
                table.add_row(
                    e.timestamp.strftime("%H:%M:%S"),
                    e.source_ip,
                    e.method,
                    e.path[:40],
                    str(e.response_status or "-"),
                    e.classification.value,
                    e.trap_type or "-",
                )
            console.print(table)


@main.command(name="mcp-client")
@click.pass_context
def mcp_client(ctx: click.Context) -> None:
    """Start the MCP server for researcher access to honeypot data."""
    console.print("[bold green]Starting Sundew MCP server...[/bold green]")

    import asyncio

    from sundew.mcp_client import run_mcp_server

    cfg = ctx.obj["config"]
    asyncio.run(run_mcp_server(cfg))


if __name__ == "__main__":
    main()
