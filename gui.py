# gui.py
#
# The graphical interface for MagicScan.
# Built with Tkinter — Python's built-in GUI library.
#
# New concepts introduced here:
#
#   CLASS — a blueprint for creating objects that hold both data and functions.
#   We create one class called MagicScanApp. It holds everything the app needs.
#
#   def __init__(self, root):
#       This is the "constructor" — it runs automatically when the app starts.
#       It sets up all the widgets (buttons, labels, tables, etc.)
#
#   self
#       Inside a class, "self" means "this specific app instance".
#       self.results_table is the table BELONGING TO this app.

import os
import json
import threading
import socket
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES

# Import our existing scanner engine — nothing changes there
from scanner import scan_file, virustotal_lookup

# Pillow — already installed, now used for image preview too
try:
    from PIL import Image, ImageTk
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# pypdf — PDF text extraction
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# Path where the user's settings (API key etc.) are saved locally
SETTINGS_FILE = Path.home() / ".magicscan_settings.json"
# ── Colour palette ─────────────────────────────────────────────────────────────
COLORS = {
    "bg":          "#0a0e1a",
    "surface":     "#111827",
    "surface2":    "#1a2235",
    "border":      "#1e2d45",
    "accent":      "#00d4ff",
    "text":        "#e2e8f0",
    "muted":       "#64748b",
    "clean":       "#10b981",
    "warning":     "#f59e0b",
    "threat":      "#ef4444",
}

STATUS_COLORS = {
    "CLEAN":    COLORS["clean"],
    "UNKNOWN":  COLORS["warning"],
    "WARNING":  COLORS["warning"],
    "MISMATCH": COLORS["threat"],
    "THREAT":   COLORS["threat"],
}

STATUS_SYMBOLS = {
    "CLEAN":    "✓  CLEAN",
    "UNKNOWN":  "?  UNKNOWN",
    "WARNING":  "!  WARNING",
    "MISMATCH": "✗  MISMATCH",
    "THREAT":   "✗  THREAT",
}


class MagicScanApp:
    """
    The main application class.
    Everything the app needs lives inside here.
    """

    def __init__(self, root):
        """
        Constructor — runs once when the app starts.
        'root' is the main Tkinter window passed in from the bottom of this file.
        """
        self.root = root
        self.root.title("MagicScan — File Type Validator")
        self.root.geometry("900x650")
        self.root.minsize(750, 500)
        self.root.configure(bg=COLORS["bg"])

        # This list will store all scan results so we can reference them later
        self.results = []

        # Build each section of the UI
        self._build_header()
        self._build_dropzone()
        self._build_toolbar()
        self._build_main_area()
        self._build_statusbar()

        # Make the window columns and rows resize proportionally
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)
        self.root.after(100, self._set_pane_split)

    # ──────────────────────────────────────────────────────────────────────────
    # UI BUILDING METHODS
    # Each method builds one section of the interface.
    # ──────────────────────────────────────────────────────────────────────────

    def _build_header(self):
        """Top banner with the app name."""
        header = tk.Frame(self.root, bg=COLORS["surface"], pady=14)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="🔬  MagicScan",
            font=("Monospace", 18, "bold"),
            fg=COLORS["accent"],
            bg=COLORS["surface"],
        ).grid(row=0, column=0)

        tk.Label(
            header,
            text="File Type Validator via Magic Numbers",
            font=("Sans", 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
        ).grid(row=1, column=0)

    def _build_dropzone(self):
        """
        A visual drop zone beneath the header.
        Users can drag files from their file manager and drop them here.

        drop_target_register(DND_FILES) tells the widget to accept file drops.
        dnd_bind('<<Drop>>', handler) calls our handler when files are dropped.
        """
        zone = tk.Frame(
            self.root,
            bg=COLORS["surface2"],
            pady=14,
            cursor="hand2",
        )
        zone.grid(row=1, column=0, sticky="ew", padx=16, pady=(8, 0))
        zone.columnconfigure(0, weight=1)

        self.drop_label = tk.Label(
            zone,
            text="⬇   Drop files or folders here",
            font=("Sans", 11),
            fg=COLORS["muted"],
            bg=COLORS["surface2"],
            pady=10,
        )
        self.drop_label.grid(row=0, column=0)

        zone.drop_target_register(DND_FILES)
        zone.dnd_bind("<<Drop>>", self._on_drop)

        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind("<<Drop>>", self._on_drop)

        zone.dnd_bind("<<DragEnter>>", lambda e: self._drop_hover(True))
        zone.dnd_bind("<<DragLeave>>", lambda e: self._drop_hover(False))
        self.drop_label.dnd_bind("<<DragEnter>>", lambda e: self._drop_hover(True))
        self.drop_label.dnd_bind("<<DragLeave>>", lambda e: self._drop_hover(False))

        self._drop_zone_frame = zone

    def _drop_hover(self, hovering):
        """Change the drop zone colour when a file is dragged over it."""
        if hovering:
            self._drop_zone_frame.configure(bg=COLORS["surface"])
            self.drop_label.configure(
                bg=COLORS["surface"],
                fg=COLORS["accent"],
                text="⬇   Release to scan",
            )
        else:
            self._drop_zone_frame.configure(bg=COLORS["surface2"])
            self.drop_label.configure(
                bg=COLORS["surface2"],
                fg=COLORS["muted"],
                text="⬇   Drop files or folders here",
            )

    def _on_drop(self, event):
        """
        Called when files are dropped onto the drop zone.

        event.data contains the dropped paths as a single string.
        On Linux, multiple files look like: {/path/file1} {/path/file2}
        The braces wrap paths that contain spaces.
        """
        self._drop_hover(False)

        raw = event.data.strip()
        paths = []
        i = 0
        while i < len(raw):
            if raw[i] == "{":
                end = raw.index("}", i)
                paths.append(raw[i + 1:end])
                i = end + 1
            elif raw[i] == " ":
                i += 1
            else:
                end = raw.find(" ", i)
                if end == -1:
                    paths.append(raw[i:])
                    break
                paths.append(raw[i:end])
                i = end + 1

        all_files = []
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for f in files:
                        all_files.append(os.path.join(root, f))
            elif os.path.isfile(path):
                all_files.append(path)

        if all_files:
            self._scan_paths(all_files)

    def _build_toolbar(self):
        """
        The row of buttons under the header.
        Each button calls a method when clicked.
        """
        toolbar = tk.Frame(self.root, bg=COLORS["bg"], pady=10, padx=16)
        toolbar.grid(row=2, column=0, sticky="ew")

        def add_button(text, command, accent=False):
            color = COLORS["accent"] if accent else COLORS["muted"]
            btn = tk.Button(
                toolbar,
                text=text,
                command=command,
                font=("Sans", 10),
                fg=color,
                bg=COLORS["surface2"],
                activeforeground=COLORS["accent"],
                activebackground=COLORS["surface"],
                relief="flat",
                cursor="hand2",
                padx=14,
                pady=6,
                bd=0,
            )
            btn.pack(side="left", padx=4)
            return btn

        add_button("＋  Add File(s)",   self.open_files,   accent=True)
        add_button("📁  Scan Folder",   self.open_folder)
        add_button("📄  Export Report", self.export_report)
        add_button("🗑  Clear Results", self.clear_results)
        add_button("⚙  Settings",       self._open_settings_dialog)

        self.stat_total = self._stat_label(toolbar, "0 scanned")
        self.stat_clean = self._stat_label(toolbar, "0 clean", COLORS["clean"])
        self.stat_flagged = self._stat_label(toolbar, "0 flagged", COLORS["threat"])

    def _stat_label(self, parent, text, color=None):
        """Helper: creates a small stat counter label on the right of the toolbar."""
        lbl = tk.Label(
            parent,
            text=text,
            font=("Monospace", 9),
            fg=color or COLORS["muted"],
            bg=COLORS["bg"],
            padx=10,
        )
        lbl.pack(side="right")
        return lbl

    def _build_main_area(self):
        """
        The central area — split into two panels:
          Left (wider)  : the results table
          Right         : details panel for the selected row
        """
        self.paned = tk.PanedWindow(
            self.root,
            orient="horizontal",
            bg=COLORS["border"],
            sashwidth=4,
            sashrelief="flat",
        )
        self.paned.grid(row=3, column=0, sticky="nsew", padx=0, pady=0)

        left = tk.Frame(self.paned, bg=COLORS["bg"])
        self.paned.add(left, minsize=400, stretch="always")
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        tk.Label(
            left,
            text="  Scan Results",
            font=("Sans", 10, "bold"),
            fg=COLORS["muted"],
            bg=COLORS["bg"],
            anchor="w",
            pady=8,
            padx=10,
        ).grid(row=0, column=0, sticky="ew")

        cols = ("status", "filename", "type", "size")
        self.tree = ttk.Treeview(
            left,
            columns=cols,
            show="headings",
            selectmode="browse",
        )

        self.tree.heading("status", text="Status")
        self.tree.heading("filename", text="Filename")
        self.tree.heading("type", text="Detected Type")
        self.tree.heading("size", text="Size")

        self.tree.column("status", width=110, anchor="center", stretch=False)
        self.tree.column("filename", width=180, anchor="w")
        self.tree.column("type", width=180, anchor="w")
        self.tree.column("size", width=70, anchor="e", stretch=False)

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["surface"],
            rowheight=30,
            font=("Sans", 10),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["surface2"],
            foreground=COLORS["muted"],
            font=("Sans", 9, "bold"),
            relief="flat",
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", COLORS["border"])])

        self.tree.tag_configure("CLEAN", foreground=COLORS["clean"])
        self.tree.tag_configure("WARNING", foreground=COLORS["warning"])
        self.tree.tag_configure("UNKNOWN", foreground=COLORS["warning"])
        self.tree.tag_configure("MISMATCH", foreground=COLORS["threat"])
        self.tree.tag_configure("THREAT", foreground=COLORS["threat"])

        scrollbar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=1, column=0, sticky="nsew")
        scrollbar.grid(row=1, column=1, sticky="ns")

        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

       # ── Right panel: tabbed (Details + Preview) ──────────────────
        right = tk.Frame(self.paned, bg=COLORS["surface"], width=280)
        self.paned.add(right, minsize=220, stretch="never")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        # Style the notebook (tab container) to match dark theme
        style = ttk.Style()
        style.configure(
            "Dark.TNotebook",
            background=COLORS["surface"],
            borderwidth=0,
            padding=0,
        )
        style.configure(
            "Dark.TNotebook.Tab",
            padding=(12, 6),
        )
        style.layout("Dark.TNotebook", [
            ("Notebook.client", {"sticky": "nswe"})
        ])
        style.configure(
            "Dark.TNotebook.Tab",
            background=COLORS["surface2"],
            foreground=COLORS["muted"],
            padding=(12, 6),
            font=("Sans", 9),
        )
        style.map(
            "Dark.TNotebook.Tab",
            background=[("selected", COLORS["surface"])],
            foreground=[("selected", COLORS["accent"])],
        )

        # Create the notebook (tab container)
        self.notebook = ttk.Notebook(right, style="Dark.TNotebook")
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)

        # ── Tab 1: Details ────────────────────────────────────────────
        details_tab = tk.Frame(self.notebook, bg=COLORS["surface"])
        details_tab.columnconfigure(0, weight=1)
        details_tab.rowconfigure(0, weight=1)
        self.notebook.add(details_tab, text="  Details  ")

        self.detail_box = tk.Text(
            details_tab,
            font=("Monospace", 9),
            fg=COLORS["text"],
            bg=COLORS["surface"],
            relief="flat",
            padx=12,
            pady=10,
            wrap="word",
            state="disabled",
            cursor="arrow",
            bd=0,
        )
        self.detail_box.grid(row=0, column=0, sticky="nsew")

        # Add a scrollbar to the details tab
        details_scroll = ttk.Scrollbar(
            details_tab,
            orient="vertical",
            command=self.detail_box.yview,
        )
        self.detail_box.configure(yscrollcommand=details_scroll.set)
        details_scroll.grid(row=0, column=1, sticky="nsew")

        self.detail_box.tag_configure("heading", foreground=COLORS["accent"],  font=("Monospace", 9, "bold"))
        self.detail_box.tag_configure("ok",      foreground=COLORS["clean"])
        self.detail_box.tag_configure("warn",    foreground=COLORS["warning"])
        self.detail_box.tag_configure("danger",  foreground=COLORS["threat"])
        self.detail_box.tag_configure("muted",   foreground=COLORS["muted"])
        self.detail_box.tag_configure("value",   foreground=COLORS["text"])

        # ── Tab 2: Preview ────────────────────────────────────────────
        preview_tab = tk.Frame(self.notebook, bg=COLORS["surface"])
        preview_tab.columnconfigure(0, weight=1)
        preview_tab.rowconfigure(0, weight=1)
        self.notebook.add(preview_tab, text="  Preview  ")

        # Scrollable canvas for the preview content
        # We use a Canvas so we can display both images and text
        # in the same container and scroll through them
        self.preview_canvas = tk.Canvas(
            preview_tab,
            bg=COLORS["surface"],
            bd=0,
            highlightthickness=0,
        )
        preview_scroll = ttk.Scrollbar(
            preview_tab,
            orient="vertical",
            command=self.preview_canvas.yview,
        )
        self.preview_canvas.configure(yscrollcommand=preview_scroll.set)
        self.preview_canvas.grid(row=0, column=0, sticky="nsew")
        preview_scroll.grid(row=0, column=1, sticky="ns")

        # Inner frame inside the canvas — this is where content goes
        self.preview_inner = tk.Frame(self.preview_canvas, bg=COLORS["surface"])
        self.preview_canvas_window = self.preview_canvas.create_window(
            (0, 0),
            window=self.preview_inner,
            anchor="nw",
        )

        # Make the inner frame resize with the canvas width
        self.preview_canvas.bind("<Configure>", self._on_preview_canvas_resize)
        self.preview_inner.bind("<Configure>",  self._on_preview_inner_resize)

        self._show_placeholder()
        
        self.detail_box.grid(row=1, column=0, sticky="nsew")

        self.detail_box.tag_configure("heading", foreground=COLORS["accent"], font=("Monospace", 9, "bold"))
        self.detail_box.tag_configure("ok", foreground=COLORS["clean"])
        self.detail_box.tag_configure("warn", foreground=COLORS["warning"])
        self.detail_box.tag_configure("danger", foreground=COLORS["threat"])
        self.detail_box.tag_configure("muted", foreground=COLORS["muted"])
        self.detail_box.tag_configure("value", foreground=COLORS["text"])

        self._show_placeholder()

    def _build_statusbar(self):
        """
        Status bar at the bottom — two sections:
          Left  : activity messages (what the app is doing)
          Right : internet connectivity indicator
        
        We use a Frame containing two Labels so we can
        align one left and one right independently.
        """
        bar = tk.Frame(self.root, bg=COLORS["surface"])
        bar.grid(row=4, column=0, sticky="ew")
        bar.columnconfigure(0, weight=1)   # left side expands
        bar.columnconfigure(1, weight=0)   # right side stays fixed

        # Left — activity messages
        self.statusbar = tk.Label(
            bar,
            text="  Ready — add files to begin scanning",
            font=("Sans", 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
            anchor="w",
            pady=5,
            padx=10,
        )
        self.statusbar.grid(row=0, column=0, sticky="ew")

        # Right — internet indicator
        self.net_indicator = tk.Label(
            bar,
            text="  Checking...  ",
            font=("Sans", 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
            anchor="e",
            pady=5,
            padx=10,
        )
        self.net_indicator.grid(row=0, column=1, sticky="e")

        # Start checking connectivity immediately
        self._check_connectivity()

    def open_files(self):
        """Open a file-picker dialog."""
        paths = filedialog.askopenfilenames(title="Select files to scan")
        if paths:
            self._scan_paths(list(paths))

    def open_folder(self):
        """Open a folder-picker dialog and scan every file inside."""
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            all_files = []
            for root, dirs, files in os.walk(folder):
                for f in files:
                    all_files.append(os.path.join(root, f))
            self._scan_paths(all_files)

    def clear_results(self):
        """Remove all rows from the table and reset counters."""
        self.results = []
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._update_stats()
        self._show_placeholder()
        self._set_status("Results cleared.")

    def _scan_paths(self, paths):
        """Start scanning in a background thread."""
        self._set_status(f"Scanning {len(paths)} file(s)...")
        thread = threading.Thread(
            target=self._scan_worker,
            args=(paths,),
            daemon=True,
        )
        thread.start()

    def export_report(self):
        """
        Generate a self-contained HTML report and save it to disk.

        Steps:
          1. Check there's something to export
          2. Ask the user where to save it (file dialog)
          3. Build the HTML string
          4. Write it to the chosen path
          5. Ask if they want to open it in the browser
        """
        if not self.results:
            messagebox.showwarning(
                "Nothing to export",
                "Scan some files first before exporting a report."
            )
            return

        # Ask user where to save
        filepath = filedialog.asksaveasfilename(
            title="Save Report As",
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("All Files", "*.*")],
            initialfile="magicscan_report.html",
        )

        if not filepath:
            return   # user cancelled the dialog

        # Build and write the report
        html = self._build_html_report()

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not save report:\n{e}")
            return

        self._set_status(f"Report saved: {filepath}")

        # Offer to open it immediately
        open_now = messagebox.askyesno(
            "Report Saved",
            f"Report saved successfully.\n\nOpen it in your browser now?"
        )
        if open_now:
            import webbrowser
            webbrowser.open(f"file://{filepath}")


    def _build_html_report(self):
        """
        Build the full HTML report as one big string and return it.

        We use Python's triple-quoted strings to write the HTML.
        f-strings let us inject live data directly into the template.

        The report is fully self-contained:
          - All CSS is inside a <style> tag
          - All data is embedded inline
          - No internet connection needed to open it
        """
        from datetime import datetime

        # ── Summary counts ────────────────────────────────────────────
        total   = len(self.results)
        clean   = sum(1 for r in self.results if r.get("status") == "CLEAN")
        flagged = total - clean
        threats  = sum(1 for r in self.results if r.get("status") == "THREAT")
        mismatch = sum(1 for r in self.results if r.get("status") == "MISMATCH")
        warnings = sum(1 for r in self.results if r.get("status") in ("WARNING", "UNKNOWN"))
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Status styling helpers ────────────────────────────────────
        # Maps status → CSS class name (defined in the <style> block below)
        def status_class(status):
            return {
                "CLEAN":    "clean",
                "UNKNOWN":  "warn",
                "WARNING":  "warn",
                "MISMATCH": "threat",
                "THREAT":   "threat",
            }.get(status, "warn")

        def status_symbol(status):
            return {
                "CLEAN":    "✓",
                "UNKNOWN":  "?",
                "WARNING":  "!",
                "MISMATCH": "✗",
                "THREAT":   "✗",
            }.get(status, "?")

        # ── Build the results rows ────────────────────────────────────
        # We build each row as a string and join them all together
        rows_html = ""
        details_html = ""

        for i, r in enumerate(self.results):
            status  = r.get("status", "UNKNOWN")
            cls     = status_class(status)
            symbol  = status_symbol(status)
            row_id  = f"detail_{i}"

            # Table row — clicking it reveals the detail block below
            rows_html += f"""
            <tr class="row-{cls}" onclick="toggle('{row_id}')">
                <td><span class="badge {cls}">{symbol} {status}</span></td>
                <td class="filename">{r.get('filename', '')}</td>
                <td>{r.get('detected_type', 'Unknown')}</td>
                <td>.{r.get('extension', '')}</td>
                <td class="mono">{r.get('size_readable', '')}</td>
            </tr>
            <tr id="{row_id}" class="detail-row" style="display:none;">
                <td colspan="5">
                    {self._build_detail_block(r)}
                </td>
            </tr>
            """

        # ── Assemble the full HTML document ──────────────────────────
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MagicScan Report — {timestamp}</title>
<style>
  /* ── Reset & base ── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0a0e1a;
    color: #e2e8f0;
    min-height: 100vh;
    padding: 0 0 40px;
  }}

  /* ── Header ── */
  .header {{
    background: #111827;
    border-bottom: 1px solid #1e2d45;
    padding: 28px 40px 20px;
  }}
  .header h1 {{
    font-size: 26px;
    color: #00d4ff;
    font-family: monospace;
    letter-spacing: -0.5px;
  }}
  .header .subtitle {{
    color: #64748b;
    font-size: 13px;
    margin-top: 4px;
  }}
  .timestamp {{
    color: #64748b;
    font-size: 12px;
    font-family: monospace;
    margin-top: 6px;
  }}

  /* ── Summary bar ── */
  .summary {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    padding: 20px 40px;
    background: #0a0e1a;
  }}
  .stat-card {{
    background: #111827;
    border: 1px solid #1e2d45;
    border-radius: 10px;
    padding: 16px;
    text-align: center;
  }}
  .stat-card .number {{
    font-size: 28px;
    font-family: monospace;
    font-weight: 700;
    line-height: 1;
  }}
  .stat-card .label {{
    font-size: 11px;
    color: #64748b;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .num-total   {{ color: #00d4ff; }}
  .num-clean   {{ color: #10b981; }}
  .num-flagged {{ color: #ef4444; }}
  .num-warn    {{ color: #f59e0b; }}
  .num-threat  {{ color: #ef4444; }}

  /* ── Table ── */
  .table-wrap {{
    padding: 0 40px;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  thead th {{
    background: #1a2235;
    color: #64748b;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid #1e2d45;
  }}
  tbody tr {{
    border-bottom: 1px solid #1a2235;
    cursor: pointer;
    transition: background 0.15s;
  }}
  tbody tr:hover {{ background: #1a2235; }}
  td {{ padding: 10px 14px; vertical-align: middle; }}

  /* Row tints */
  .row-clean   {{ background: rgba(16,185,129,0.04); }}
  .row-warn    {{ background: rgba(245,158,11,0.04); }}
  .row-threat  {{ background: rgba(239,68,68,0.05); }}

  /* ── Badges ── */
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.4px;
    font-family: monospace;
  }}
  .clean  {{ background: rgba(16,185,129,0.15);  color: #10b981; }}
  .warn   {{ background: rgba(245,158,11,0.15);  color: #f59e0b; }}
  .threat {{ background: rgba(239,68,68,0.15);   color: #ef4444; }}

  /* ── Detail block (expandable) ── */
  .detail-row td {{ padding: 0; }}
  .detail-block {{
    background: #111827;
    border-left: 3px solid #1e2d45;
    padding: 16px 20px;
    font-size: 12px;
  }}
  .detail-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
    margin-bottom: 12px;
  }}
  .detail-section h4 {{
    font-family: monospace;
    font-size: 10px;
    color: #00d4ff;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }}
  .detail-section p {{
    color: #64748b;
    font-size: 11px;
    margin-bottom: 2px;
  }}
  .detail-section span {{
    color: #e2e8f0;
    font-family: monospace;
    font-size: 11px;
    word-break: break-all;
  }}
  .finding {{
    background: rgba(239,68,68,0.08);
    border-left: 3px solid #ef4444;
    padding: 6px 10px;
    margin-top: 6px;
    font-size: 11px;
    color: #ef4444;
    border-radius: 0 4px 4px 0;
  }}
  .hex {{
    font-family: monospace;
    font-size: 11px;
    color: #64748b;
    background: #1a2235;
    padding: 6px 10px;
    border-radius: 4px;
    word-break: break-all;
  }}
  .mono {{ font-family: monospace; }}
  .filename {{ font-family: monospace; font-weight: 600; }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    color: #1e2d45;
    font-size: 11px;
    margin-top: 40px;
    font-family: monospace;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🔬 MagicScan</h1>
  <div class="subtitle">File Type Validator — Magic Number Analysis Report</div>
  <div class="timestamp">Generated: {timestamp}</div>
</div>

<div class="summary">
  <div class="stat-card"><div class="number num-total">{total}</div><div class="label">Total Scanned</div></div>
  <div class="stat-card"><div class="number num-clean">{clean}</div><div class="label">Clean</div></div>
  <div class="stat-card"><div class="number num-flagged">{flagged}</div><div class="label">Flagged</div></div>
  <div class="stat-card"><div class="number num-warn">{warnings}</div><div class="label">Warnings</div></div>
  <div class="stat-card"><div class="number num-threat">{threats + mismatch}</div><div class="label">Threats</div></div>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Status</th>
        <th>Filename</th>
        <th>Detected Type</th>
        <th>Extension</th>
        <th>Size</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>

<div class="footer">MagicScan — Cybersecurity Portfolio Project</div>

<script>
  // Toggle the detail row when a file row is clicked
  function toggle(id) {{
    var row = document.getElementById(id);
    row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
  }}
</script>

</body>
</html>"""

        return html


    def _build_detail_block(self, r):
        """
        Build the HTML for one file's expandable detail block.
        Called once per result row inside _build_html_report.
        """
        status = r.get("status", "UNKNOWN")
        cls    = {
            "CLEAN": "clean", "UNKNOWN": "warn", "WARNING": "warn",
            "MISMATCH": "threat", "THREAT": "threat",
        }.get(status, "warn")

        # ── Findings ──────────────────────────────────────────────────
        findings_html = ""
        for finding in r.get("findings") or []:
            findings_html += f'<div class="finding">⚠ {finding}</div>'

        # ── Hashes ────────────────────────────────────────────────────
        hashes_html = f"""
        <div class="detail-section">
            <h4>File Hashes</h4>
            <p>MD5</p><span>{r.get('md5', 'n/a')}</span><br><br>
            <p>SHA-1</p><span>{r.get('sha1', 'n/a')}</span><br><br>
            <p>SHA-256</p><span>{r.get('sha256', 'n/a')}</span>
        </div>"""

        # ── Metadata ──────────────────────────────────────────────────
        metadata     = r.get("metadata", {})
        fields       = metadata.get("fields", []) if metadata else []
        meta_flag    = metadata.get("flag") if metadata else None
        metadata_html = ""

        if fields:
            metadata_html += '<div class="detail-section"><h4>Metadata</h4>'
            for label, value in fields:
                metadata_html += f"<p>{label}</p><span>{value}</span><br>"
            if meta_flag:
                metadata_html += f'<br><div class="finding">{meta_flag}</div>'
            metadata_html += "</div>"

        # ── Probability matches ───────────────────────────────────────
        probs      = r.get("probabilities", [])
        probs_html = ""

        if probs:
            probs_html += '<div class="detail-section"><h4>Probability Match</h4>'
            for match in probs:
                pct   = match["percentage"]
                label = match["label"]
                color = "#ef4444" if match["threat"] else (
                        "#10b981" if pct >= 80 else
                        "#f59e0b" if pct >= 50 else "#64748b")
                probs_html += f"""
                <div style="margin-bottom:6px;">
                  <span style="font-family:monospace;color:{color};font-size:11px;">
                    {pct:>3}%
                  </span>
                  <span style="font-size:11px;color:#e2e8f0;margin-left:8px;">{label}</span>
                </div>"""
            probs_html += "</div>"

        return f"""
        <div class="detail-block">
          {findings_html}
          <div class="detail-grid">
            <div class="detail-section">
              <h4>File Info</h4>
              <p>Full path</p><span>{r.get('filepath', '')}</span><br><br>
              <p>Detected type</p><span>{r.get('detected_type', '')}</span><br><br>
              <p>Extension</p><span>.{r.get('extension', '')}</span><br><br>
              <p>File size</p><span>{r.get('size_readable', '')}</span>
            </div>
            <div class="detail-section">
              <h4>Hex Header</h4>
              <div class="hex">{r.get('hex_header', '')}</div>
            </div>
            {hashes_html}
            {metadata_html}
            {probs_html}
          </div>
        </div>"""

    def _scan_worker(self, paths):
        """The actual scanning logic — runs inside the background thread."""
        for filepath in paths:
            result = scan_file(filepath)
            self.root.after(0, self._add_result_row, result)

        self.root.after(0, self._set_status, f"Done — {len(paths)} file(s) scanned.")

    def _add_result_row(self, result):
        """Insert one result into the table."""
        if "error" in result:
            self.tree.insert(
                "", "end",
                values=("ERROR", result.get("error", ""), "", ""),
                tags=("THREAT",),
            )
            self._update_stats()
            return

        self.results.append(result)

        status_text = STATUS_SYMBOLS.get(result["status"], result["status"])

        self.tree.insert(
            "",
            "end",
            iid=str(len(self.results) - 1),
            values=(
                status_text,
                result["filename"],
                result["detected_type"],
                result["size_readable"],
            ),
            tags=(result["status"],),
        )

        self._update_stats()

    def _on_row_select(self, event):
        """Called when the user clicks a row in the table."""
        selected = self.tree.selection()
        if not selected:
            return
        row_id = selected[0]
        try:
            index  = int(row_id)
            result = self.results[index]
            self._show_details(result)
            self._show_preview(result)   # ← add this line
        except (ValueError, IndexError):
            pass

    def _write_detail(self, text, tag=None):
        """Helper: append a line to the detail box."""
        self.detail_box.configure(state="normal")
        if tag:
            self.detail_box.insert("end", text, tag)
        else:
            self.detail_box.insert("end", text)
        self.detail_box.configure(state="disabled")

    def _set_pane_split(self):
        """
        Set the paned window to a 70/30 split after the window
        has fully loaded and we know its actual width.

        We use root.after(100) to delay this call slightly —
        if we run it too early the window width is 0.
        """
        total = self.root.winfo_width()
        if total > 100:
            split = int(total * 0.70)
            self.paned.sash_place(0, split, 0)  

    def _on_preview_canvas_resize(self, event):
        """Keep the inner preview frame the same width as the canvas."""
        self.preview_canvas.itemconfig(
            self.preview_canvas_window,
            width=event.width,
        )

    def _on_preview_inner_resize(self, event):
        """Update the scroll region when content is added or removed."""
        self.preview_canvas.configure(
            scrollregion=self.preview_canvas.bbox("all")
        )

    def _show_placeholder(self):
        """Show instructions when no row is selected."""
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("1.0", "  Click any row to see details.", "muted")
        self.detail_box.configure(state="disabled")

    def _show_details(self, result):
        """Fill the detail panel with info about a scanned file."""
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        self.detail_box.configure(state="disabled")

        status = result.get("status", "UNKNOWN")
        color_tag = {
            "CLEAN": "ok",
            "UNKNOWN": "warn",
            "WARNING": "warn",
            "MISMATCH": "danger",
            "THREAT": "danger",
        }.get(status, "value")

        def line(label, value, tag="value"):
            self._write_detail(f"\n  {label}\n", "muted")
            self._write_detail(f"  {value}\n", tag)

        self._write_detail("\n  ── SCAN RESULT ──\n", "heading")
        line("Filename",      result.get("filename", ""))
        line("Status",        STATUS_SYMBOLS.get(status, status), color_tag)
        line("Detected type", result.get("detected_type", ""))
        extension = result.get("extension")
        line("Extension",     f".{extension or '(none)'}")
        line("File size",     result.get("size_readable", ""))

        # ── Inline format/color summary ───────────────────────────────
        # Pull these from metadata if available for a quick summary
        # at the top of the panel — mirrors the wireframe design
        metadata = result.get("metadata", {})
        fields   = dict(metadata.get("fields", [])) if metadata else {}
        fmt      = fields.get("Format") or result.get("detected_type", "")
        mode     = fields.get("Color mode")
        dims     = fields.get("Dimensions")

        if fmt or mode or dims:
            summary_parts = []
            if fmt:   summary_parts.append(f"Format: {fmt}")
            if mode:  summary_parts.append(f"Color: {mode}")
            if dims:  summary_parts.append(f"Size: {dims}")
            self._write_detail("\n  " + "   •   ".join(summary_parts) + "\n", "muted")

        self._write_detail("\n  ── HEX HEADER ──\n", "heading")
        self._write_detail(f"\n  {result.get('hex_header', '')}\n", "muted")

        findings = result.get("findings") or []
        if findings:
            self._write_detail("\n  ── FINDINGS ──\n", "heading")
            for finding in findings:
                for fline in finding.split("\n"):
                    self._write_detail(f"\n  → {fline}\n", color_tag)
        else:
            self._write_detail("\n  No issues found.\n", "ok")

            # ── Probability matches ──────────────────────────────────────
        probabilities = result.get("probabilities", [])
        if probabilities:

            # ── Metadata ─────────────────────────────────────────────────
            metadata = result.get("metadata", {})
        fields   = metadata.get("fields", [])
        flag     = metadata.get("flag")

        if fields:
            self._write_detail("\n  ── METADATA ──\n", "heading")
            for label, value in fields:
                self._write_detail(f"\n  {label}\n", "muted")
                self._write_detail(f"  {value}\n", "value")

        if flag:
            self._write_detail(f"\n  {flag}\n", "danger")
            self._write_detail("\n  ── PROBABILITY MATCH ──\n", "heading")
            for match in probabilities:
                pct     = match["percentage"]
                label   = match["label"]
                threat  = match["threat"]

                # Pick colour based on score and threat level
                if threat:
                    bar_tag = "danger"
                elif pct >= 80:
                    bar_tag = "ok"
                elif pct >= 50:
                    bar_tag = "warn"
                else:
                    bar_tag = "muted"

                # Build a simple text progress bar
                # Each "█" block represents 5%
                # 100% = 20 blocks, 50% = 10 blocks, etc.
                filled = round(pct / 5)
                empty  = 20 - filled
                bar    = "█" * filled + "░" * empty

                self._write_detail(f"\n  {pct:>3}%  ", bar_tag)
                self._write_detail(f"{bar}  ", bar_tag)
                self._write_detail(f"{label}\n", "value")

            self._write_detail("\n  ── FILE HASHES ──\n", "heading")
        self._render_hash_row("MD5",     result.get("md5",    "n/a"))
        self._render_hash_row("SHA-1",   result.get("sha1",   "n/a"))
        self._render_hash_row("SHA-256", result.get("sha256", "n/a"))

        # ── VirusTotal button ─────────────────────────────────────────
        self.detail_box.configure(state="normal")
        self.detail_box.insert("end", "\n  ")

        vt_btn = tk.Button(
            self.detail_box,
            text="🛡  Check for Malware",
            font=("Sans", 9),
            fg=COLORS["accent"],
            bg=COLORS["surface2"],
            activeforeground=COLORS["bg"],
            activebackground=COLORS["accent"],
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=10,
            pady=4,
            command=lambda: self._run_virustotal(result),
        )
        self.detail_box.window_create("end", window=vt_btn)
        self.detail_box.insert("end", "\n")
        self.detail_box.configure(state="disabled")

        # Placeholder where the VT result will appear
        # We tag this spot so we can insert results here later
        self.detail_box.configure(state="normal")
        self.detail_box.insert("end", "\n", "vt_result_anchor")
        self.detail_box.configure(state="disabled")

        self._write_detail("\n  ── FULL PATH ──\n", "heading")
        self._write_detail(f"\n  {result.get('filepath', '')}\n", "muted")

    def _clear_preview(self):
        """Remove all widgets from the preview panel."""
        for widget in self.preview_inner.winfo_children():
            widget.destroy()
        # Keep a reference to any PhotoImage to prevent garbage collection
        # Tkinter will blank out images if the Python object is deleted
        self._preview_image_ref = None


    def _preview_message(self, message, tag="muted"):
        """Show a simple text message in the preview panel."""
        self._clear_preview()
        colors = {
            "muted":  COLORS["muted"],
            "danger": COLORS["threat"],
            "ok":     COLORS["clean"],
        }
        tk.Label(
            self.preview_inner,
            text=message,
            font=("Sans", 10),
            fg=colors.get(tag, COLORS["muted"]),
            bg=COLORS["surface"],
            wraplength=240,
            justify="center",
            pady=20,
        ).pack(pady=30, padx=10)


    def _show_preview(self, result):
        """
        Decide which preview to show based on detected file type.
        Called whenever a row is selected, alongside _show_details.
        """
        self._clear_preview()

        filepath     = result.get("filepath", "")
        detected     = result.get("detected_type", "").lower()
        extension    = result.get("extension", "").lower()

        # ── Image preview ─────────────────────────────────────────────
        is_image = any(word in detected for word in
                       ["jpeg", "png", "gif", "bmp", "webp", "tiff", "image"])

        if is_image:
            self._preview_image(filepath)
            return

        # ── Text preview ──────────────────────────────────────────────
        text_extensions = [
            "txt", "csv", "json", "xml", "html", "htm",
            "md", "py", "js", "css", "sh", "yaml", "yml",
            "ini", "cfg", "log", "rtf",
        ]
        if extension in text_extensions:
            self._preview_text(filepath)
            return

        # ── PDF preview ───────────────────────────────────────────────
        if "pdf" in detected or extension == "pdf":
            self._preview_pdf(filepath)
            return

        # ── Fallback ──────────────────────────────────────────────────
        self._preview_message(
            f"Preview not available for this file type.\n\n"
            f"({result.get('detected_type', 'Unknown')})\n\n"
            f"Check the Details tab for metadata and hashes.",
            tag="muted",
        )


    def _preview_image(self, filepath):
        """
        Load and display an image using Pillow.

        We resize it to fit the panel width (max 260px wide)
        while keeping the aspect ratio — so tall images don't
        overflow the panel and wide images don't get cut off.

        ImageTk.PhotoImage is the bridge between Pillow and Tkinter.
        We MUST keep a reference to it (self._preview_image_ref)
        otherwise Python's garbage collector deletes it and the
        image goes blank.
        """
        if not PILLOW_AVAILABLE:
            self._preview_message("Pillow not installed — cannot preview images.")
            return

        try:
            img = Image.open(filepath)

            # Resize to fit panel, max 260px wide
            max_width  = 260
            max_height = 320
            img.thumbnail((max_width, max_height), Image.LANCZOS)

            # Convert to Tkinter-compatible format
            photo = ImageTk.PhotoImage(img)

            # Store reference to prevent garbage collection
            self._preview_image_ref = photo

            # Display the image
            img_label = tk.Label(
                self.preview_inner,
                image=photo,
                bg=COLORS["surface"],
            )
            img_label.pack(pady=10)

            # Show dimensions below the image
            tk.Label(
                self.preview_inner,
                text=f"{img.width} × {img.height} px  •  {img.mode}",
                font=("Sans", 8),
                fg=COLORS["muted"],
                bg=COLORS["surface"],
            ).pack()

        except Exception as e:
            self._preview_message(f"Could not load image:\n{e}", tag="danger")


    def _preview_text(self, filepath, max_lines=50):
        """
        Read and display the first N lines of a text file.

        We try UTF-8 first (most common encoding).
        If that fails we fall back to latin-1 which can read
        almost any byte sequence without crashing.
        """
        try:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                with open(filepath, "r", encoding="latin-1") as f:
                    lines = f.readlines()

            preview_lines = lines[:max_lines]
            content       = "".join(preview_lines)
            truncated     = len(lines) > max_lines

            text_widget = tk.Text(
                self.preview_inner,
                font=("Monospace", 8),
                fg=COLORS["text"],
                bg=COLORS["surface2"],
                relief="flat",
                padx=8,
                pady=8,
                wrap="none",
                state="normal",
                bd=0,
                height=30,
            )
            text_widget.pack(fill="both", expand=True, padx=4, pady=4)
            text_widget.insert("1.0", content)
            text_widget.configure(state="disabled")

            if truncated:
                tk.Label(
                    self.preview_inner,
                    text=f"Showing first {max_lines} of {len(lines)} lines",
                    font=("Sans", 8),
                    fg=COLORS["muted"],
                    bg=COLORS["surface"],
                ).pack(pady=4)

        except Exception as e:
            self._preview_message(f"Could not read file:\n{e}", tag="danger")


    def _preview_pdf(self, filepath, max_pages=3):
        """
        Extract and display text from the first few pages of a PDF.

        pypdf reads the PDF structure and extracts the raw text.
        This won't look exactly like the PDF — formatting, columns,
        and images are lost — but the text content comes through.
        """
        if not PYPDF_AVAILABLE:
            self._preview_message("pypdf not installed — cannot preview PDFs.")
            return

        try:
            reader  = pypdf.PdfReader(filepath)
            total   = len(reader.pages)
            pages   = min(max_pages, total)
            content = []

            for i in range(pages):
                text = reader.pages[i].extract_text()
                if text:
                    content.append(f"── Page {i + 1} ──\n{text.strip()}")

            if not content:
                self._preview_message(
                    "No text found in this PDF.\n\n"
                    "It may be a scanned image PDF.",
                    tag="muted",
                )
                return

            full_text = "\n\n".join(content)

            text_widget = tk.Text(
                self.preview_inner,
                font=("Sans", 9),
                fg=COLORS["text"],
                bg=COLORS["surface2"],
                relief="flat",
                padx=8,
                pady=8,
                wrap="word",
                state="normal",
                bd=0,
                height=30,
            )
            text_widget.pack(fill="both", expand=True, padx=4, pady=4)
            text_widget.insert("1.0", full_text)
            text_widget.configure(state="disabled")

            if total > max_pages:
                tk.Label(
                    self.preview_inner,
                    text=f"Showing {pages} of {total} pages",
                    font=("Sans", 8),
                    fg=COLORS["muted"],
                    bg=COLORS["surface"],
                ).pack(pady=4)

        except Exception as e:
            self._preview_message(f"Could not read PDF:\n{e}", tag="danger")

    def _update_stats(self):
        """Recount and update the three stat labels in the toolbar."""
        total = len(self.results)
        clean = sum(1 for r in self.results if r.get("status") == "CLEAN")
        flagged = sum(1 for r in self.results if r.get("status") in ("THREAT", "MISMATCH", "WARNING", "UNKNOWN"))

        self.stat_total.config(text=f"{total} scanned")
        self.stat_clean.config(text=f"{clean} clean")
        self.stat_flagged.config(text=f"{flagged} flagged")


    def _render_hash_row(self, label, hash_value):
        """
        Render one hash row with a truncated value and a copy button.

        We use a Frame embedded inside the Text widget via
        text.window_create() — this is how you put real widgets
        (like buttons) inside a Tkinter Text widget.

        The hash is truncated to 16 chars for display but the
        copy button copies the full value.
        """
        # Truncate for display: "85c9f13d4a2b1e8f..."
        truncated = hash_value[:16] + "..." if len(hash_value) > 16 else hash_value

        # Enable the text widget briefly to insert content
        self.detail_box.configure(state="normal")

        # Write the label and truncated hash as normal text
        self.detail_box.insert("end", f"\n  {label}\n", "muted")
        self.detail_box.insert("end", f"  {truncated}   ", "value")

        # Create the copy button as a real widget
        btn = tk.Button(
            self.detail_box,
            text="📋",
            font=("Sans", 8),
            fg=COLORS["muted"],
            bg=COLORS["surface2"],
            activeforeground=COLORS["accent"],
            activebackground=COLORS["surface"],
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=4,
            pady=1,
            # lambda captures hash_value for this specific row
            command=lambda v=hash_value: self._copy_to_clipboard(v),
        )

        # Embed the button widget inside the text widget
        self.detail_box.window_create("end", window=btn)
        self.detail_box.insert("end", "\n")
        self.detail_box.configure(state="disabled")

        
    def _run_virustotal(self, result):
        """
        Called when the user clicks Check for Malware.

        Flow:
          1. Check if an API key is saved
          2. If not → open the settings dialog with a callback
             that runs the lookup after the key is saved
          3. If yes → run the lookup directly
          4. If key is invalid → open settings dialog again
        """
        sha256 = result.get("sha256", "")

        if not sha256 or sha256 == "unavailable":
            self._set_status("No SHA-256 hash available for this file.")
            return

        api_key = self._load_api_key()

        if not api_key:
            # No key saved — open dialog, pass lookup as callback
            self._open_settings_dialog(
                on_save=lambda: self._do_virustotal_lookup(result)
            )
            return

        self._do_virustotal_lookup(result)


    def _do_virustotal_lookup(self, result):
        """
        The actual lookup — separated from _run_virustotal so it
        can be called both directly and as an on_save callback.
        """
        sha256  = result.get("sha256", "")
        api_key = self._load_api_key()

        self._set_status("Querying VirusTotal...")

        def lookup():
            vt_result = virustotal_lookup(sha256, api_key)

            # If key is invalid, open settings dialog on main thread
            if not vt_result.get("success") and vt_result.get("error") == "invalid_key":
                self.root.after(
                    0,
                    lambda: self._open_settings_dialog(
                        on_save=lambda: self._do_virustotal_lookup(result)
                    )
                )
                self.root.after(
                    0,
                    self._set_status,
                    "Invalid API key — please update it in Settings.",
                )
                return

            self.root.after(0, self._show_vt_result, vt_result)

        thread = threading.Thread(target=lookup, daemon=True)
        thread.start()
   

    def _show_vt_result(self, vt):
        """
        Display the VirusTotal result in the details panel.
        Called on the main thread via root.after().
        """
        self.detail_box.configure(state="normal")

        # Find the anchor tag we placed and insert results there
        try:
            anchor = self.detail_box.tag_ranges("vt_result_anchor")
            if anchor:
                self.detail_box.delete(anchor[0], "end")
        except Exception:
            pass

        self.detail_box.insert("end", "\n  ── VIRUSTOTAL RESULT ──\n", "heading")

        if not vt.get("success"):
            self.detail_box.insert(
                "end",
                f"\n  ✗ {vt.get('error', 'Unknown error')}\n",
                "danger",
            )
            self._set_status("VirusTotal lookup failed.")

        elif not vt.get("found"):
            self.detail_box.insert("end", "\n  Status\n",   "muted")
            self.detail_box.insert("end", "  ✓ NOT MALWARE\n", "ok")
            

        else:
            # Verdict color
            verdict     = vt.get("verdict", "UNKNOWN")
            verdict_tag = {
                "CLEAN":      "ok",
                "SUSPICIOUS": "warn",
                "MALICIOUS":  "danger",
            }.get(verdict, "warn")

            verdict_symbol = {
                "CLEAN":      "✓",
                "SUSPICIOUS": "!",
                "MALICIOUS":  "✗",
            }.get(verdict, "?")

            self.detail_box.insert("end", f"\n  Engines scanned\n",   "muted")
            self.detail_box.insert("end", f"  {vt.get('total', 0)}\n", "value")

            self.detail_box.insert("end", f"\n  Detections\n", "muted")
            self.detail_box.insert(
                "end",
                f"  {vt.get('detections', 0)} / {vt.get('total', 0)}\n",
                verdict_tag,
            )

            flagged = vt.get("flagged_by", [])
            if flagged:
                self.detail_box.insert("end", f"\n  Flagged by\n", "muted")
                self.detail_box.insert(
                    "end",
                    f"  {', '.join(flagged)}\n",
                    "danger",
                )

            self.detail_box.insert("end", f"\n  Verdict\n", "muted")
            self.detail_box.insert(
                "end",
                f"  {verdict_symbol}  {verdict}\n",
                verdict_tag,
            )

            self.detail_box.insert("end", f"\n  Full report\n", "muted")
            self.detail_box.insert(
                "end",
                f"  {vt.get('link', '')}\n",
                "muted",
            )

            self._set_status(
                f"VirusTotal: {vt.get('detections', 0)} detection(s) — {verdict}"
            )

        self.detail_box.configure(state="disabled")

    def _load_api_key(self):
        """
        Load the saved API key from settings.json.
        Returns the key string or None if not set.
        """
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, "r") as f:
                    data = json.load(f)
                    return data.get("virustotal_api_key", None)
        except Exception:
            pass
        return None


    def _save_api_key(self, key):
        """
        Save the API key to settings.json in the home directory.
        We load existing settings first so we don't overwrite
        other saved preferences in the future.
        """
        data = {}
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, "r") as f:
                    data = json.load(f)
        except Exception:
            pass

        data["virustotal_api_key"] = key.strip()

        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not save settings:\n{e}")
            return False


    def _open_settings_dialog(self, on_save=None):
        """
        Open the API key settings dialog.

        on_save is an optional callback — if provided, it gets
        called after the user successfully saves a key.
        This lets the malware check button trigger the lookup
        automatically after the user sets their key for the
        first time.

        We use tk.Toplevel() to create a child window that
        sits on top of the main app.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("VirusTotal API Key")
        dialog.geometry("480x400")
        dialog.resizable(False, False)
        dialog.configure(bg=COLORS["bg"])
        dialog.grab_set()   # makes the dialog modal — blocks the main window

        # Centre the dialog over the main window
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width()  // 2) - 240
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 200
        dialog.geometry(f"+{x}+{y}")

        # ── Header ────────────────────────────────────────────────────
        tk.Label(
            dialog,
            text="🛡  Check for Malware",
            font=("Monospace", 14, "bold"),
            fg=COLORS["accent"],
            bg=COLORS["bg"],
        ).pack(pady=(20, 4))

        tk.Label(
            dialog,
            text="Powered by VirusTotal — 70+ antivirus engines",
            font=("Sans", 9),
            fg=COLORS["muted"],
            bg=COLORS["bg"],
        ).pack()

        # ── Divider ───────────────────────────────────────────────────
        tk.Frame(dialog, bg=COLORS["border"], height=1).pack(
            fill="x", padx=20, pady=16
        )

        # ── How to get a key ──────────────────────────────────────────
        tk.Label(
            dialog,
            text="How to get your free API key:",
            font=("Sans", 10, "bold"),
            fg=COLORS["text"],
            bg=COLORS["bg"],
            anchor="w",
        ).pack(anchor="w", padx=24)

        steps = [
            "1.  Go to virustotal.com and sign up for a free account",
            "2.  Click your profile icon in the top right corner",
            "3.  Select  API Key  from the dropdown menu",
            "4.  Copy your key and paste it in the field below",
        ]
        for step in steps:
            tk.Label(
                dialog,
                text=step,
                font=("Sans", 9),
                fg=COLORS["muted"],
                bg=COLORS["bg"],
                anchor="w",
                justify="left",
            ).pack(anchor="w", padx=32, pady=1)

        # Clickable link to VirusTotal
        link = tk.Label(
            dialog,
            text="  → Open virustotal.com",
            font=("Sans", 9, "underline"),
            fg=COLORS["accent"],
            bg=COLORS["bg"],
            cursor="hand2",
            anchor="w",
        )
        link.pack(anchor="w", padx=28, pady=(6, 0))
        link.bind("<Button-1>", lambda e: __import__("webbrowser").open("https://www.virustotal.com"))

        # ── Divider ───────────────────────────────────────────────────
        tk.Frame(dialog, bg=COLORS["border"], height=1).pack(
            fill="x", padx=20, pady=16
        )

        # ── Key input ─────────────────────────────────────────────────
        tk.Label(
            dialog,
            text="Paste your API key here:",
            font=("Sans", 10, "bold"),
            fg=COLORS["text"],
            bg=COLORS["bg"],
            anchor="w",
        ).pack(anchor="w", padx=24, pady=(0, 6))

        # Load existing key — show it masked if already saved
        existing_key = self._load_api_key() or ""
        key_var = tk.StringVar(value=existing_key)

        key_entry = tk.Entry(
            dialog,
            textvariable=key_var,
            font=("Monospace", 10),
            fg=COLORS["text"],
            bg=COLORS["surface2"],
            insertbackground=COLORS["accent"],
            relief="flat",
            bd=0,
            show="•",          # mask the key like a password field
        )
        key_entry.pack(fill="x", padx=24, ipady=8)

        # Show/hide toggle
        show_var = tk.BooleanVar(value=False)
        def toggle_show():
            key_entry.configure(show="" if show_var.get() else "•")

        tk.Checkbutton(
            dialog,
            text="Show key",
            variable=show_var,
            command=toggle_show,
            font=("Sans", 9),
            fg=COLORS["muted"],
            bg=COLORS["bg"],
            selectcolor=COLORS["surface2"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["muted"],
            bd=0,
        ).pack(anchor="w", padx=24, pady=(4, 0))

        # ── Buttons ───────────────────────────────────────────────────
        btn_frame = tk.Frame(dialog, bg=COLORS["bg"])
        btn_frame.pack(pady=16, padx=24, fill="x")

        def on_save_click():
            key = key_var.get().strip()
            if not key:
                messagebox.showwarning(
                    "No Key",
                    "Please paste your API key before saving.",
                    parent=dialog,
                )
                return
            if self._save_api_key(key):
                self._set_status("API key saved successfully.")
                dialog.destroy()
                if on_save:
                    on_save()   # trigger the lookup if called from malware check

        tk.Button(
            btn_frame,
            text="Save & Scan",
            command=on_save_click,
            font=("Sans", 10, "bold"),
            fg=COLORS["bg"],
            bg=COLORS["accent"],
            activeforeground=COLORS["bg"],
            activebackground=COLORS["accent"],
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=16,
            pady=6,
        ).pack(side="left")

        tk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            font=("Sans", 10),
            fg=COLORS["muted"],
            bg=COLORS["surface2"],
            activeforeground=COLORS["text"],
            activebackground=COLORS["surface"],
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=16,
            pady=6,
        ).pack(side="left", padx=(8, 0))          



    def _copy_to_clipboard(self, text):
        """
        Copy a string to the system clipboard.

        root.clipboard_clear() wipes whatever was there before.
        root.clipboard_append() puts our text in.
        The clipboard only persists while the app is open in some
        systems — root.clipboard_clear() + append is the safe pattern.
        """
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status(f"Copied to clipboard: {text[:20]}...") 


    def _check_connectivity(self):
        """
        Check internet connectivity in a background thread
        so it never blocks the UI.

        We run this check once immediately on startup, then
        schedule it to repeat every 10 seconds automatically
        using root.after().

        Why 8.8.8.8? It's Google's public DNS server — it's
        always online and responds instantly. We're not sending
        any data, just testing if a TCP connection can be opened.
        Port 53 is the standard DNS port.
        """
        def check():
            connected = False
            try:
                # Try to open a socket connection — timeout after 3 seconds
                sock = socket.create_connection(("8.8.8.8", 53), timeout=3)
                sock.close()
                connected = True
            except (socket.timeout, socket.error, OSError):
                connected = False

            # Schedule the UI update back on the main thread
            self.root.after(0, self._update_net_indicator, connected)

        thread = threading.Thread(target=check, daemon=True)
        thread.start()

        # Schedule the next check in 10 seconds
        self.root.after(10000, self._check_connectivity)


    def _update_net_indicator(self, connected):
        """
        Update the internet indicator label based on connectivity.
        Called on the main thread via root.after().
        """
        if connected:
            self.net_indicator.configure(
                text="  🌐 Online  ",
                fg=COLORS["clean"],
            )
        else:
            self.net_indicator.configure(
                text="  ⚠  Offline — VirusTotal unavailable  ",
                fg=COLORS["warning"],
            )       

    def _set_status(self, message):
        """Update the status bar at the bottom."""
        self.statusbar.config(text=f"  {message}")


if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = MagicScanApp(root)
    root.mainloop()
