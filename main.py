import sys
import threading
import time
import webbrowser

from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """
[bold green]  ███████╗███████╗ ██████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗[/bold green]
[bold green]  ██╔════╝██╔════╝██╔════╝██╔══██╗██║   ██║██╔══██╗██║╚══██══╝[/bold green]
[bold green]  ███████╗█████╗  ██║     ███████║██║   ██║██║  ██║██║   ██║   [/bold green]
[bold green]  ╚════██║██╔══╝  ██║     ██╔══██║██║   ██║██║  ██║██║   ██║   [/bold green]
[bold green]  ███████║███████╗╚██████╗██║  ██║╚██████╔╝██████╔╝██║   ██║   [/bold green]
[bold green]  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   [/bold green]
"""

DISCLAIMER = """
[bold red]⚠️  LEGAL DISCLAIMER & WARNING  ⚠️[/bold red]
This tool is strictly for [bold]educational purposes[/bold] and [bold]authorized security auditing[/bold] only.
You must have explicit, written permission from the owner of the target system before running this scanner.
Unauthorized scanning or attacking of targets without consent is illegal and punishable by law.
The developer assumes no liability for any misuse or damage caused by this program.
"""


def run_web_server():
    from web_ui import app, socketio
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, use_reloader=False)


def main():
    console.print(Panel(BANNER, border_style='green', expand=False))
    console.print(Panel(DISCLAIMER, border_style='red', expand=True))

    while True:
        console.print("\n[bold yellow]Select an option to proceed:[/bold yellow]")
        console.print("[bold green]1.[/bold green] Localhost (Launch Modern Web UI)")
        console.print("[bold green]2.[/bold green] Terminal (Run in CLI Mode)")
        console.print("[bold red]3.[/bold red] Exit")

        choice = console.input("\n[bold cyan]Enter your choice (1/2/3):[/bold cyan] ").strip()

        if choice == '1':
            console.print("\n[bold green]Initializing Web UI Server...[/bold green]")
            threading.Thread(target=run_web_server, daemon=True).start()
            time.sleep(2)
            console.print("[bold green]Server started. Opening browser automatically...[/bold green]")
            webbrowser.open('http://127.0.0.1:5000')
            console.print("\n[bold yellow]Web UI is running on http://127.0.0.1:5000[/bold yellow]")
            console.print("[bold yellow]Press Ctrl+C to stop the server and exit.[/bold yellow]")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[bold red]Shutting down server. Goodbye![/bold red]")
                sys.exit(0)

        elif choice == '2':
            from cli import run_cli
            run_cli()

        elif choice == '3':
            console.print("\n[bold green]Exiting. Stay ethical![/bold green]")
            sys.exit(0)
        else:
            console.print("[bold red]Invalid choice. Please select 1, 2, or 3.[/bold red]")


if __name__ == '__main__':
    main()