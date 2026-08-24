from rich.console import Console
from rich.theme import Theme
from datetime import datetime

_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error":   "bold red",
    "debug":   "dim white",
    "target":  "bold magenta",
    "data":    "bright_white",
})

console = Console(theme=_theme, emoji=False)

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def info(msg: str):    console.print(f"[dim]{_ts()}[/] [[info]INF[/]] {msg}")
def success(msg: str): console.print(f"[dim]{_ts()}[/] [[success]OK [/]] {msg}")
def warning(msg: str): console.print(f"[dim]{_ts()}[/] [[warning]WRN[/]] {msg}")
def error(msg: str):   console.print(f"[dim]{_ts()}[/] [[error]ERR[/]] {msg}")
def debug(msg: str):   console.print(f"[dim]{_ts()}[/] [[debug]DBG[/]] {msg}")
def data(msg: str):    console.print(f"[dim]{_ts()}[/] [[data]DAT[/]] {msg}")
def target(msg: str):  console.print(f"[dim]{_ts()}[/] [[target]TGT[/]] {msg}")
def banner(msg: str):  console.print(f"\n[bold cyan]{msg}[/]\n")
