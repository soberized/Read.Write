import os
import ctypes

# -- ANSI ---------------------------------------------------------------
pink  = "\033[38;5;213m"
reset = "\033[0m"

# -- Icons -------------------------------------------------------------------

def icon(symbol: str = "!") -> str:
    return f"[{pink}{symbol}{reset}]"

INFO    = icon("!")   # [!]
SUCCESS = icon("+")   # [+]
WARN    = icon("*")   # [*]
ARROW   = icon(">")   # [>]
DASH    = icon("-")   # [-]
DOT     = icon(".")   # [.]
HASH    = icon("#")   # [#]
AT      = icon("@")   # [@]
CHECK   = icon("/")   # [/]
CROSS   = icon("X")   # [X]


# -- Logging ------------------------------------------------------------

def log(msg: str, prefix: str = INFO):
    print(f" {prefix} {msg}")

def info(msg: str):
    log(msg, INFO)

def success(msg: str):
    log(msg, SUCCESS)

def warn(msg: str):
    log(msg, WARN)


# -- Console ----------------------------------------------------------

def enable_ansi():
    os.system("")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def title(text: str):
    if os.name == "nt":
        ctypes.windll.kernel32.SetConsoleTitleW(text)
    else:
        print(f"\033]0;{text}\007", end="", flush=True)

def banner(version: str = "Python", author: str = "soberized"):
    print(f"""
 read.{pink}write.{reset} | Version {pink}@{reset} {version}
 Developed by {pink}{author}{reset}
""")


# -- Import Runs ------------------------------------------------------
enable_ansi()
