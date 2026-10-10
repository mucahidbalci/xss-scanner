import asyncio
import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from payloads import load_custom_wordlist
from scanner import VulnerabilityScanner

console = Console()


def run_cli():
    console.print(Panel(
        "[bold red]TERMINAL MODE[/bold red]\n"
        "Active scanning will be performed from this machine.\n"
        "Only scan systems you own or have written permission to test.",
        border_style='yellow',
    ))

    target_url = console.input("\n[bold cyan]Enter target URL:[/bold cyan] ").strip()
    if not target_url:
        console.print("[bold red]No target provided. Returning to menu.[/bold red]")
        return
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    mode_raw = console.input(
        "[bold cyan]Payload mode [s]tandard fast / [f]ull deep (default s):[/bold cyan] "
    ).strip().lower()
    payload_mode = 'full' if mode_raw.startswith('f') else 'standard'

    wordlist = None
    wordlist_path = console.input(
        "[bold cyan]Optional custom wordlist path, SecLists compatible (Enter to skip):[/bold cyan] "
    ).strip()
    if wordlist_path:
        if os.path.isfile(wordlist_path):
            wordlist = load_custom_wordlist(wordlist_path)
            console.print(f"[bold green]Loaded {len(wordlist)} payloads from {wordlist_path}[/bold green]")
        else:
            console.print("[bold red]Wordlist file not found. Continuing with built-in library.[/bold red]")

    console.print(f"\n[bold green]Starting asynchronous scan on {target_url} ...[/bold green]\n")

    scanner = VulnerabilityScanner(
        target_url, socketio=None,
        payload_mode=payload_mode, custom_wordlist=wordlist,
    )
    scan_data = asyncio.run(scanner.run_scan())

    results = scan_data['results']
    vulns = [r for r in results if r['type'] == 'vulnerability']

    table = Table(title='Scan Results', border_style='green', header_style='bold magenta')
    table.add_column('Severity', style='bold')
    table.add_column('Finding', style='white')

    if not vulns:
        table.add_row('[bold blue]INFO[/bold blue]', 'No vulnerabilities detected on the target surface.')

    for v in vulns:
        color = {'Critical': 'red', 'High': 'red', 'Medium': 'yellow', 'Low': 'blue'}.get(v.get('severity'), 'white')
        detail = f"[bold]{v['title']}[/bold]\n"
        detail += f"Category: {v.get('category', 'n/a')}\n"
        if v.get('url'):
            detail += f"URL: {v['url']}\n"
        if v.get('payload'):
            detail += f"Evidence: {v['payload']}\n"
        if v.get('description'):
            detail += f"{v['description']}\n"
        detail += f"CVSS: {v.get('cvss', 'N/A')}"
        table.add_row(f"[bold {color}]{v.get('severity', 'INFO').upper()}[/bold {color}]", detail)

    console.print(table)

    if scan_data.get('tech_stack'):
        console.print(Panel('Detected: ' + ', '.join(scan_data['tech_stack']),
                            title='Technology Stack', border_style='green'))

    console.print(f"\n[bold green]Scan finished in {scan_data['duration']}s "
                  f"with {len(vulns)} finding(s).[/bold green]")
    console.input("\n[bold yellow]Press Enter to return to the main menu...[/bold yellow]")