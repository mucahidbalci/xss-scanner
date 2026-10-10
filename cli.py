from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from scanner import XSSScanner

console = Console()


def run_cli():
    console.print(Panel("[bold red]TERMINAL MODE[/bold red]\nPlease ensure you have authorization to scan the target.",
                        border_style="yellow"))

    target_url = console.input("\n[bold cyan]Enter target URL (e.g., http://testphp.vulnweb.com):[/bold cyan] ").strip()

    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'http://' + target_url

    console.print(f"\n[bold green]Initializing scan for:[/bold green] {target_url}\n")

    scanner = XSSScanner(target_url)
    results = scanner.scan()

    table = Table(title="Scan Results", border_style="cyan", header_style="bold magenta")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="white")

    for res in results:
        if res['type'] == 'vulnerability':
            status = "[bold red]VULNERABLE[/bold red]"
            details = (
                f"[bold]URL:[/bold] {res['url']}\n"
                f"[bold]Method:[/bold] {res['method']}\n"
                f"[bold]Payload:[/bold] {res['payload']}\n"
                f"[bold]Inputs:[/bold] {', '.join(res['inputs'])}"
            )
            table.add_row(status, details)
        elif res['type'] == 'error':
            table.add_row("[bold red]ERROR[/bold red]", res['message'])
        else:
            table.add_row("[bold blue]INFO[/bold blue]", res['message'])

    console.print(table)
    console.input("\n[bold yellow]Press Enter to return to the main menu...[/bold yellow]")