# main.py
#
# This is the entry point — the file you actually run.
# It handles:
#   - Reading the filename you give it
#   - Printing results in a readable, colourful format
#   - Scanning whole folders if you want

import sys
import os
from scanner import scan_file


# ── Terminal colours ──────────────────────────────────────────────────────────
# These are special escape codes that tell the terminal to change text colour.
# \033[ starts the code, the number picks the colour, m ends it.
# RESET always goes at the end to go back to normal.
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def color_for_status(status):
    """Return the right colour code for a given status string."""
    colors = {
        "CLEAN":    GREEN,
        "UNKNOWN":  YELLOW,
        "WARNING":  YELLOW,
        "MISMATCH": RED,
        "THREAT":   RED,
    }
    return colors.get(status, WHITE)


def print_banner():
    """Print the tool name at the top when it starts."""
    print(f"""
{CYAN}{BOLD}  ╔╦╗┌─┐┌─┐┬┌─┐╔═╗┌─┐┌─┐┌┐┌{RESET}
{CYAN}{BOLD}  ║║║├─┤│ ┬││  ╚═╗│  ├─┤│││{RESET}
{CYAN}{BOLD}  ╩ ╩┴ ┴└─┘┴└─┘╚═╝└─┘┴ ┴┘└┘{RESET}
{DIM}  File Type Validator — Magic Number Edition{RESET}
{DIM}  Cybersecurity Portfolio Project{RESET}
""")


def print_divider():
    print(f"  {DIM}{'─' * 54}{RESET}")


def print_result(result):
    """
    Print one scan result in a readable format.

    We use f-strings for formatting:
      f"Hello {name}" → inserts the value of 'name' into the string
    """
    if "error" in result:
        print(f"\n  {RED}ERROR: {result['error']}{RESET}")
        return

    status = result["status"]
    color  = color_for_status(status)

    # Pick a symbol based on status
    symbols = {
        "CLEAN":    "✓",
        "UNKNOWN":  "?",
        "WARNING":  "!",
        "MISMATCH": "✗",
        "THREAT":   "✗",
    }
    symbol = symbols.get(status, "?")

    print()
    print_divider()
    print(f"  {BOLD}{WHITE}File      :{RESET} {result['filename']}")
    print(f"  Status    : {color}{BOLD}{symbol} {status}{RESET}")
    print(f"  Detected  : {WHITE}{result['detected_type']}{RESET}")
    print(f"  Extension : .{result['extension'] or '(none)'}")
    print(f"  Size      : {result['size_readable']}")
    print(f"  Hex header: {DIM}{result['hex_header']}{RESET}")

    if result["findings"]:
        print(f"\n  {BOLD}Findings:{RESET}")
        for finding in result["findings"]:
            # Each line of the finding gets an arrow prefix
            for line in finding.split("\n"):
                print(f"  {color}  → {line}{RESET}")


def scan_single_file(filepath):
    """Scan one file and print the result."""
    result = scan_file(filepath)
    print_result(result)
    print()


def scan_folder(folder_path):
    """
    Walk through every file in a folder (including subfolders) and scan each one.

    os.walk() is a Python built-in that visits every subfolder automatically.
    It gives you back three things each loop:
      root  = current folder path
      dirs  = list of subfolders inside root
      files = list of files inside root
    """
    print(f"\n{CYAN}  Scanning folder:{RESET} {folder_path}")

    counts = {"CLEAN": 0, "UNKNOWN": 0, "WARNING": 0, "MISMATCH": 0, "THREAT": 0}
    total  = 0

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            result   = scan_file(filepath)
            print_result(result)
            total += 1
            if "status" in result:
                counts[result["status"]] = counts.get(result["status"], 0) + 1

    # Summary
    print()
    print_divider()
    print(f"  {BOLD}SCAN COMPLETE — {total} file(s){RESET}")
    print(f"  {GREEN}✓ Clean    : {counts['CLEAN']}{RESET}")
    print(f"  {YELLOW}! Warnings : {counts['WARNING'] + counts['UNKNOWN']}{RESET}")
    print(f"  {RED}✗ Threats  : {counts['THREAT'] + counts['MISMATCH']}{RESET}")
    print_divider()
    print()


def main():
    """
    The main function — this is what runs when you start the program.

    sys.argv is a list of everything you typed on the command line.
      sys.argv[0] = "main.py"  (the script name, always first)
      sys.argv[1] = the path you typed after it (if you gave one)
    """
    print_banner()

    if len(sys.argv) < 2:
        # User didn't type a path — ask them for one
        print(f"  {DIM}Tip: you can also run:  python3 main.py /path/to/file{RESET}\n")
        target = input(f"  {CYAN}Enter a file or folder path to scan:{RESET} ").strip()
    else:
        target = sys.argv[1]

    if not target:
        print(f"\n  {RED}No path given. Exiting.{RESET}\n")
        return

    # Decide if the path is a file or a folder
    if os.path.isdir(target):
        scan_folder(target)
    elif os.path.isfile(target):
        scan_single_file(target)
    else:
        print(f"\n  {RED}Path not found: {target}{RESET}\n")
        print(f"  {DIM}Make sure the path exists and you typed it correctly.{RESET}\n")


# This line means: only run main() if this file is run directly.
# If another file imports scanner.py, main() won't fire automatically.
if __name__ == "__main__":
    main()
