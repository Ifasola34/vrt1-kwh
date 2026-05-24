"""vrt1-kwh — CLI for the kWh attestation oracle.

Subcommands:
  keygen       generate a fresh BIP-340 device key
  measure      take ONE measurement with the chosen measurer and print
  run          run the oracle daemon: tick every --interval seconds
  verify       check a SignedMeasurement file's signature
  aggregate    sum a directory of SignedMeasurements + report gaps + fraud
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from veritas.crypto import OracleKey

from .aggregator import aggregate
from .attestation import SignedMeasurement, make_measurement, sign_measurement
from .measurer import RaplMeasurer, StubMeasurer, SubprocessMeasurer
from .oracle import KwhOracle, OracleConfig, load_corpus


console = Console()


def _resolve_measurer(name: str, kwh_per_second: float):
    """Map a CLI --measurer name to an instance.

    Subprocess and other parameterized measurers need richer wiring;
    the CLI exposes the no-frills cases here. For custom subprocess
    measurers, write a small Python wrapper rather than overloading
    the CLI.
    """
    if name == "stub":
        return StubMeasurer(kwh_per_second=kwh_per_second)
    if name == "rapl":
        try:
            return RaplMeasurer()
        except FileNotFoundError as e:
            raise click.ClickException(str(e))
    raise click.ClickException(
        f"unknown measurer {name!r}; one of: stub, rapl. "
        "For subprocess-based measurers, use the Python API."
    )


@click.group()
def cli() -> None:
    """vrt1-kwh — signed kWh attestations for the VERITAS protocol."""


@cli.command()
@click.option("--out", type=click.Path(), default="device.key", show_default=True)
def keygen(out: str) -> None:
    """Generate a fresh BIP-340 device key.

    Created with mode 0600 atomically — no TOCTOU window where another
    local process can read the privkey. Refuses to overwrite.
    """
    key = OracleKey.generate()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(out, flags, 0o600)
    except FileExistsError:
        raise click.ClickException(
            f"refusing to overwrite existing key file: {out}"
        )
    except OSError as e:
        raise click.ClickException(f"cannot create key file {out}: {e}")
    try:
        os.write(fd, (key.privkey.hex() + "\n").encode("ascii"))
    finally:
        os.close(fd)
    console.print(Panel.fit(
        f"[bold green]device key created[/bold green]\n"
        f"x-only pubkey: [yellow]{key.xonly_pubkey_hex}[/yellow]\n"
        f"saved to {out} (mode 0600)",
    ))


@cli.command()
@click.option("--key", "key_path", type=click.Path(exists=True), required=True,
              help="Device BIP-340 key (hex). Use `vrt1-kwh keygen` to create.")
@click.option("--measurer", type=click.Choice(["stub", "rapl"]),
              default="stub", show_default=True)
@click.option("--duration", type=float, default=10.0, show_default=True,
              help="Measurement window length in seconds.")
@click.option("--stub-kwh-per-second", type=float, default=0.00001,
              show_default=True, help="StubMeasurer rate (kWh/s) — ignored for other measurers.")
@click.option("--out", type=click.Path(), default=None,
              help="Write the signed measurement to this file (default: stdout).")
def measure(
    key_path: str, measurer: str, duration: float,
    stub_kwh_per_second: float, out: str | None,
) -> None:
    """Take a single measurement and sign it."""
    try:
        key = OracleKey.from_hex(Path(key_path).read_text().strip())
    except ValueError as e:
        raise click.ClickException(f"invalid key file: {e}")
    m = _resolve_measurer(measurer, stub_kwh_per_second)
    sample = m.measure(duration)
    signed = sign_measurement(
        make_measurement(
            device_pubkey_hex=key.xonly_pubkey_hex, sample=sample,
        ),
        key,
    )
    body = signed.to_json()
    if out:
        Path(out).write_text(body)
        console.print(f"[green]signed[/green] → {out}")
        console.print(f"id: [yellow]{signed.id}[/yellow]")
        console.print(f"kwh: {signed.measurement.kwh}")
    else:
        click.echo(body)


@cli.command()
@click.option("--key", "key_path", type=click.Path(exists=True), required=True)
@click.option("--data-dir", type=click.Path(), default="./kwh-data", show_default=True)
@click.option("--measurer", type=click.Choice(["stub", "rapl"]),
              default="stub", show_default=True)
@click.option("--interval", type=int, default=300, show_default=True,
              help="Seconds between measurement starts.")
@click.option("--window", type=int, default=30, show_default=True,
              help="Seconds per measurement.")
@click.option("--max-measurements", type=int, default=None,
              help="Stop after this many ticks (default: run forever).")
@click.option("--stub-kwh-per-second", type=float, default=0.00001, show_default=True)
@click.option("--unlinkable", is_flag=True,
              help="Generate a fresh random nonce per measurement so windows aren't linkable beyond the device pubkey.")
def run(
    key_path: str, data_dir: str, measurer: str,
    interval: int, window: int, max_measurements: int | None,
    stub_kwh_per_second: float, unlinkable: bool,
) -> None:
    """Run the oracle daemon: tick periodically + sign + persist."""
    try:
        key = OracleKey.from_hex(Path(key_path).read_text().strip())
    except ValueError as e:
        raise click.ClickException(f"invalid key file: {e}")
    m = _resolve_measurer(measurer, stub_kwh_per_second)
    nonce_factory = (lambda: secrets.token_hex(16)) if unlinkable else (lambda: "")
    cfg = OracleConfig(
        data_dir=Path(data_dir),
        interval_seconds=interval,
        window_seconds=window,
        max_measurements=max_measurements,
        nonce_factory=nonce_factory,
    )

    def _on_sign(sm: SignedMeasurement) -> None:
        console.print(
            f"[green]tick[/green] {sm.measurement.window_start}–{sm.measurement.window_end} "
            f"kwh={sm.measurement.kwh:.9f} id={sm.id[:12]}…"
        )

    oracle = KwhOracle(key, m, cfg, on_sign=_on_sign)
    console.print(Panel.fit(
        f"[bold]vrt1-kwh oracle running[/bold]\n"
        f"device pubkey: [yellow]{oracle.device_pubkey_hex}[/yellow]\n"
        f"data dir:      {data_dir}\n"
        f"measurer:      {measurer}\n"
        f"window/interval: {window}s every {interval}s\n"
        f"max:           {max_measurements or 'forever'}"
    ))
    try:
        taken = oracle.run()
    except KeyboardInterrupt:
        oracle.stop()
        taken = "interrupted"
    console.print(f"\nstopped — measurements taken: [bold]{taken}[/bold]")


@cli.command()
@click.argument("measurement_file", type=click.Path(exists=True))
def verify(measurement_file: str) -> None:
    """Verify a SignedMeasurement's Schnorr signature."""
    try:
        signed = SignedMeasurement.from_json(Path(measurement_file).read_text())
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise click.ClickException(f"invalid signed-measurement file: {e}")
    ok = signed.verify()
    console.print(Panel.fit(
        "[bold green]VALID[/bold green]" if ok else "[bold red]INVALID[/bold red]",
        title=f"measurement {signed.id[:16]}…",
        border_style="green" if ok else "red",
    ))
    sys.exit(0 if ok else 1)


@cli.command(name="aggregate")
@click.option("--corpus", type=click.Path(exists=True, file_okay=False), required=True,
              help="Directory containing one *.json SignedMeasurement per file.")
@click.option("--device", type=str, default=None,
              help="Limit the report to this device pubkey hex (default: every device).")
@click.option("--min-gap-seconds", type=int, default=60, show_default=True,
              help="Minimum gap to surface in the coverage report.")
def aggregate_cmd(corpus: str, device: str | None, min_gap_seconds: int) -> None:
    """Aggregate a directory of SignedMeasurements: totals + gaps + overlap fraud."""
    sms = load_corpus(Path(corpus))
    if not sms:
        raise click.ClickException(f"no parseable SignedMeasurements found in {corpus}")
    if device is not None:
        sms = [s for s in sms if s.measurement.device == device]
        if not sms:
            raise click.ClickException(
                f"no measurements for device {device[:16]}… in {corpus}"
            )

    report = aggregate(sms, min_gap_seconds=min_gap_seconds)

    t = Table(title="device totals")
    t.add_column("device"); t.add_column("kwh"); t.add_column("count")
    t.add_column("invalid"); t.add_column("first"); t.add_column("last")
    for dev, dt in report.totals.items():
        t.add_row(
            dev[:16] + "…",
            f"{dt.total_kwh:.9f}",
            str(dt.measurement_count),
            str(dt.invalid_count) if dt.invalid_count else "-",
            str(dt.first_window_start or "-"),
            str(dt.last_window_end or "-"),
        )
    console.print(t)

    if report.gaps:
        t = Table(title=f"coverage gaps ≥ {min_gap_seconds}s")
        t.add_column("device"); t.add_column("from"); t.add_column("to"); t.add_column("duration")
        for g in report.gaps:
            t.add_row(g.device[:16] + "…", str(g.gap_start), str(g.gap_end),
                      f"{g.duration_seconds}s")
        console.print(t)
    else:
        console.print("[green]no coverage gaps[/green]")

    if report.overlaps:
        t = Table(title="[bold red]OVERLAP FRAUD DETECTED[/bold red]")
        t.add_column("device"); t.add_column("a_id"); t.add_column("b_id"); t.add_column("overlap")
        for o in report.overlaps:
            t.add_row(o.device[:16] + "…", o.a_id[:12] + "…", o.b_id[:12] + "…",
                      f"{o.overlap_seconds}s")
        console.print(t)
    else:
        console.print("[green]no overlap fraud detected[/green]")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
