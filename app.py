"""
WordForge — context-aware wordlist builder for AUTHORIZED security testing.

GUI: WiFi mode, Email mode, and a Browse tab for reputable public wordlists.
Cross-platform (Linux + Windows) Tkinter app with a modern dark theme.
Ships with a built-in local password model (localmodel.py); Ollama is optional.
"""

from __future__ import annotations

import os
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import engine
import catalog
import localmodel
import baselist

APP_TITLE = "WordForge — Wordlist Builder (Authorized Testing Only)"
DISCLAIMER = (
    "For authorized security testing only. By using WordForge you confirm you "
    "have explicit written permission to test the target. Using credentials "
    "against systems you don't own or lack permission to test may be illegal."
)

# ---- palette: slate / sky / cyan (Tailwind tokens) ------------------------ #
BG        = "#0F172A"   # slate-900  app background
SURFACE   = "#1E293B"   # slate-800  cards / panels
SURFACE2  = "#334155"   # slate-700  raised / hover
FIELD     = "#0B1120"   # recessed inputs (darker than bg)
TEXT      = "#E2E8F0"   # slate-200
MUTED     = "#94A3B8"   # slate-400
ACCENT    = "#38BDF8"   # sky-400    primary accent
ACCENT2   = "#06B6D4"   # cyan-500   secondary accent
DANGER    = "#F87171"   # red-400
OK        = "#34D399"   # emerald-400
BORDER    = "#334155"   # slate-700
BORDER_HI = "#475569"   # slate-600
INK       = "#0F172A"   # dark text on accent fills
PATTERN   = "#172033"   # faint geometric lines over the header

# Tailwind spacing scale (px) used across the layout.
SP = {1: 4, 2: 8, 3: 12, 4: 16, 5: 20, 6: 24, 8: 32}


def apply_dark_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=BG)

    style.configure(".", background=BG, foreground=TEXT, fieldbackground=FIELD,
                    bordercolor=BORDER, focuscolor=ACCENT, font=("Segoe UI", 10))
    style.configure("TFrame", background=BG)
    style.configure("Surface.TFrame", background=SURFACE)
    # card: a panel with a hairline border for faux elevation
    style.configure("Card.TFrame", background=SURFACE, borderwidth=1,
                    relief="solid", bordercolor=BORDER)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Surface.TLabel", background=SURFACE, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("Danger.TLabel", background=SURFACE, foreground=DANGER)
    style.configure("Title.TLabel", background=SURFACE, foreground=TEXT,
                    font=("Segoe UI", 17, "bold"))
    style.configure("Accent.TLabel", background=BG, foreground=ACCENT,
                    font=("Segoe UI Semibold", 10))
    style.configure("Header.TLabel", background=BG, foreground=TEXT,
                    font=("Segoe UI", 13, "bold"))
    style.configure("Hint.TLabel", background=BG, foreground=MUTED,
                    font=("Segoe UI", 8))

    style.configure("TNotebook", background=BG, borderwidth=0,
                    tabmargins=(SP[2], SP[3], SP[2], 0))
    style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                    padding=(SP[6], SP[3]), font=("Segoe UI Semibold", 10),
                    borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", SURFACE)],
              foreground=[("selected", ACCENT), ("active", TEXT)])

    style.configure("TButton", background=SURFACE2, foreground=TEXT,
                    borderwidth=0, padding=(SP[4], SP[2]), font=("Segoe UI", 9))
    style.map("TButton", background=[("active", BORDER_HI), ("pressed", BORDER_HI)])
    style.configure("Accent.TButton", background=ACCENT, foreground=INK,
                    borderwidth=0, padding=(SP[5], SP[2] + 2),
                    font=("Segoe UI Semibold", 10))
    style.map("Accent.TButton",
              background=[("active", ACCENT2), ("pressed", ACCENT2),
                          ("disabled", BORDER)],
              foreground=[("disabled", MUTED)])

    style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT,
                    insertcolor=ACCENT, bordercolor=BORDER, padding=SP[2],
                    borderwidth=1)
    style.map("TEntry", bordercolor=[("focus", ACCENT)])

    style.configure("TCheckbutton", background=BG, foreground=TEXT, focuscolor=BG)
    style.map("TCheckbutton", background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT), ("!selected", FIELD)])

    style.configure("TCombobox", fieldbackground=FIELD, background=SURFACE2,
                    foreground=TEXT, arrowcolor=ACCENT, bordercolor=BORDER,
                    padding=SP[1] + 1)
    style.map("TCombobox", fieldbackground=[("readonly", FIELD)],
              foreground=[("readonly", TEXT)], bordercolor=[("focus", ACCENT)])

    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                    foreground=TEXT, bordercolor=BORDER, borderwidth=0,
                    rowheight=30, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background=BG, foreground=MUTED,
                    font=("Segoe UI Semibold", 9), padding=SP[2], borderwidth=0,
                    relief="flat")
    style.map("Treeview.Heading", background=[("active", SURFACE2)])
    style.map("Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", INK)])

    style.configure("Vertical.TScrollbar", background=SURFACE2, troughcolor=BG,
                    bordercolor=BG, arrowcolor=MUTED, borderwidth=0)
    style.map("Vertical.TScrollbar", background=[("active", ACCENT2)])

    style.configure("Status.TLabel", background=SURFACE, foreground=MUTED,
                    padding=(SP[3], SP[2]))

    root.option_add("*TCombobox*Listbox.background", SURFACE)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", INK)


def draw_header_pattern(canvas: tk.Canvas, w: int, h: int) -> None:
    """Subtle layered geometric texture (diagonal facets) + accent hairline —
    echoes the reference dashboards without gradients."""
    canvas.delete("all")
    canvas.configure(bg=SURFACE, highlightthickness=0)
    step = 26
    for x in range(-h, w, step):                 # forward diagonals
        canvas.create_line(x, h, x + h, 0, fill=PATTERN, width=1)
    for x in range(0, w + h, step * 3):           # a few brighter facets
        canvas.create_line(x, 0, x - h, h, fill="#1F2B44", width=1)
    canvas.create_line(0, h - 1, w, h - 1, fill=ACCENT, width=1)  # light-source edge


def style_text(widget: tk.Text) -> tk.Text:
    widget.configure(bg=FIELD, fg=TEXT, insertbackground=ACCENT, relief="flat",
                     highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=ACCENT, borderwidth=0, padx=SP[2], pady=SP[2],
                     selectbackground=ACCENT, selectforeground=INK)
    return widget


def run_thread(fn):
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    return t


class GenTab(ttk.Frame):
    """Shared UI for the wifi / email generation modes."""

    def __init__(self, master, profile: str, app: "WordForge"):
        super().__init__(master, padding=SP[6])
        self.profile = profile
        self.app = app
        self.results: list[str] = []

        wifi = profile == "wifi"
        head = ("WiFi mode — WPA/WPA2 passphrase candidates (8–63 chars). Only "
                "the network SSID is required; other fields are optional."
                if wifi else
                "Email mode — likely account passwords from personal context + "
                "the built-in model. (The email address itself is never used.)")
        ttk.Label(self, text=head, style="Header.TLabel", wraplength=760).grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 2))

        # per-tab base wordlist line
        base_line = ttk.Frame(self)
        base_line.grid(row=0, column=0, columnspan=4, sticky="e")
        ttk.Label(base_line, text="Builds on:", style="Hint.TLabel").pack(side="left")
        ttk.Label(base_line, textvariable=app.base_vars[profile],
                  style="Hint.TLabel").pack(side="left", padx=(4, 0))
        ttk.Button(base_line, text="Change base…",
                   command=lambda: app.choose_base(profile)).pack(side="left", padx=(8, 0))

        r = 1
        if wifi:
            self._field(r, "Network SSID (required)",
                        "the Wi-Fi network name, e.g. NETGEAR58", height=1, attr="ssid")
            r += 1
        kw_label = ("router brand, owner/family/pet names — optional" if wifi
                    else "Person's name, pet, company, hobbies, kids' names")
        self._field(r, "Keywords" + (" (optional)" if wifi else ""), kw_label,
                    height=3, attr="kw"); r += 1
        self._field(r, "Years / dates", "e.g. 1990, 2015, 07/1988",
                    height=1, attr="years"); r += 1
        self._field(r, "Numbers", "phone fragments, house no., PIN",
                    height=1, attr="nums"); r += 1
        self._field(r, "Notes (for the model)", "anything else about the target",
                    height=2, attr="notes"); r += 1

        opt = ttk.Frame(self)
        opt.grid(row=r, column=0, columnspan=4, sticky="w", pady=(10, 4)); r += 1
        self.use_leet = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Leetspeak variants", variable=self.use_leet).pack(side="left")
        ttk.Label(opt, text="Length (records):", style="Muted.TLabel").pack(side="left", padx=(18, 4))
        self.max_out = tk.StringVar(value="250000")
        ttk.Entry(opt, textvariable=self.max_out, width=10).pack(side="left")

        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self, variable=self.authorized,
            text="I confirm I am authorized to test this target.",
        ).grid(row=r, column=0, columnspan=4, sticky="w", pady=(6, 8)); r += 1

        btns = ttk.Frame(self)
        btns.grid(row=r, column=0, columnspan=4, sticky="w"); r += 1
        self.gen_btn = ttk.Button(btns, text="Generate", style="Accent.TButton",
                                  command=self.on_generate)
        self.gen_btn.pack(side="left")
        ttk.Button(btns, text="Save wordlist…", command=self.on_save).pack(side="left", padx=8)
        ttk.Button(btns, text="Clear", command=self.on_clear).pack(side="left")

        head2 = ttk.Frame(self)
        head2.grid(row=r, column=0, columnspan=4, sticky="ew", pady=(14, 4)); r += 1
        ttk.Label(head2, text="Preview (first 500)", style="Muted.TLabel").pack(side="left")
        self.count_lbl = ttk.Label(head2, text="0 records", style="Muted.TLabel")
        self.count_lbl.pack(side="right")

        self.out = style_text(tk.Text(self, height=12, wrap="none",
                                      font=("Consolas", 10)))
        self.out.grid(row=r, column=0, columnspan=4, sticky="nsew")
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.out.yview)
        yscroll.grid(row=r, column=4, sticky="ns")
        self.out.config(yscrollcommand=yscroll.set)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(r, weight=1)

    def _field(self, row, label, hint, height, attr):
        ttk.Label(self, text=label).grid(row=row, column=0, sticky="nw", pady=4, padx=(0, 10))
        if height == 1:
            w = ttk.Entry(self)
            w.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        else:
            w = style_text(tk.Text(self, height=height, wrap="word",
                                   font=("Segoe UI", 9)))
            w.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(self, text=hint, style="Hint.TLabel").grid(
            row=row, column=3, sticky="w", padx=8)
        setattr(self, attr, w)

    def _get(self, w) -> str:
        if isinstance(w, tk.Text):
            return w.get("1.0", "end").strip()
        return w.get().strip()

    def on_generate(self):
        if not self.authorized.get():
            messagebox.showwarning(
                "Authorization required",
                "Tick the authorization confirmation before generating.")
            return
        try:
            length = max(1, int(self.max_out.get().replace(",", "").strip()))
        except ValueError:
            length = 250000

        ssid = self._get(self.ssid) if hasattr(self, "ssid") else ""
        target = engine.Target.from_fields(
            self._get(self.kw), self._get(self.years),
            self._get(self.nums), self._get(self.notes), ssid=ssid)

        if self.profile == "wifi":
            if not target.ssid and not target.keywords:
                messagebox.showinfo("Need SSID", "Enter the network SSID.")
                return
        elif not target.keywords and not target.notes:
            messagebox.showinfo("Need input", "Add at least some keywords or notes.")
            return

        model = self.app.selected_model()
        base_words = self.app.base_words(self.profile)
        base_name = self.app.base_name_for(self.profile)
        self.gen_btn.config(state="disabled")
        self.app.set_status("Generating…")

        def work():
            try:
                words = engine.generate(
                    target, self.profile, model, self.use_leet.get(),
                    length, progress=self.app.set_status,
                    base_words=base_words, base_name=base_name)
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                words = []
            self.after(0, lambda: self._show(words))

        run_thread(work)

    def _show(self, words):
        self.results = words
        self.out.delete("1.0", "end")
        self.out.insert("1.0", "\n".join(words[:500]))
        self.count_lbl.config(text=f"{len(words)} records")
        self.gen_btn.config(state="normal")
        self.app.set_status(f"Ready — {len(words)} records generated.")

    def on_save(self):
        if not self.results:
            messagebox.showinfo("Nothing to save", "Generate a wordlist first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"wordforge_{self.profile}.txt",
            filetypes=[("Text wordlist", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write("\n".join(self.results))
        self.app.set_status(f"Saved {len(self.results)} candidates → {path}")
        messagebox.showinfo("Saved", f"Wrote {len(self.results)} candidates to:\n{path}")

    def on_clear(self):
        fields = [self.kw, self.years, self.nums, self.notes]
        if hasattr(self, "ssid"):
            fields.append(self.ssid)
        for w in fields:
            if isinstance(w, tk.Text):
                w.delete("1.0", "end")
            else:
                w.delete(0, "end")
        self.out.delete("1.0", "end")
        self.results = []
        self.count_lbl.config(text="0 records")


class BrowseTab(ttk.Frame):
    def __init__(self, master, app: "WordForge"):
        super().__init__(master, padding=SP[6])
        self.app = app

        ttk.Label(self, text="Reputable public wordlists (legally distributed).",
                  style="Header.TLabel").grid(row=0, column=0, columnspan=5, sticky="w")
        self.update_note = ttk.Label(self, text="Checking for updates on launch…",
                                     style="Hint.TLabel")
        self.update_note.grid(row=0, column=0, columnspan=6, sticky="e")
        self.statuses: dict[str, str] = {}

        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, columnspan=5, sticky="ew", pady=(10, 8))
        ttk.Label(bar, text="Search").pack(side="left")
        self.query = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.query, width=28)
        e.pack(side="left", padx=8)
        e.bind("<KeyRelease>", lambda _e: self.refresh())
        ttk.Label(bar, text="Category").pack(side="left", padx=(16, 6))
        self.cat = tk.StringVar(value="all")
        cb = ttk.Combobox(bar, textvariable=self.cat, values=catalog.categories(),
                          state="readonly", width=20)
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        cols = ("name", "status", "category", "size", "published")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (280, 90, 130, 120, 170)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.grid(row=2, column=0, columnspan=5, sticky="nsew")
        sc = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        sc.grid(row=2, column=5, sticky="ns")
        self.tree.config(yscrollcommand=sc.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        self.desc = style_text(tk.Text(self, height=4, wrap="word",
                                       font=("Segoe UI", 9)))
        self.desc.grid(row=3, column=0, columnspan=6, sticky="ew", pady=10)

        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, columnspan=6, sticky="w")
        ttk.Button(btns, text="Open project page", command=self.open_page).pack(side="left")
        ttk.Button(btns, text="Download to folder…", style="Accent.TButton",
                   command=self.download).pack(side="left", padx=8)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self._rows: list[catalog.WordlistInfo] = []
        self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._rows = catalog.filter_catalog(self.query.get(), self.cat.get())
        for w in self._rows:
            st = self.statuses.get(w.name, "—")
            self.tree.insert("", "end",
                             values=(w.name, st, w.category, w.approx_size, w.published))

    def set_statuses(self, statuses: dict):
        self.statuses = statuses
        fresh = sum(1 for v in statuses.values() if v in ("new", "updated"))
        self.update_note.config(
            text=(f"{fresh} new/updated available" if fresh
                  else "All tracked lists current"))
        self.refresh()

    def _current(self):
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        return self._rows[idx] if idx < len(self._rows) else None

    def on_select(self, _e):
        w = self._current()
        self.desc.delete("1.0", "end")
        if w:
            self.desc.insert("1.0", f"{w.name}\n{w.description}\n\nSource: {w.project_url}")

    def open_page(self):
        w = self._current()
        if w:
            webbrowser.open(w.project_url)

    def download(self):
        w = self._current()
        if not w:
            messagebox.showinfo("Select one", "Pick a wordlist first.")
            return
        url = w.download_url
        if url.endswith(("/wordlist", ".htm", ".html")) or "weakpass" in url or "crackstation" in url:
            if messagebox.askyesno(
                    "Reference page",
                    f"'{w.name}' is a project/reference page rather than a direct "
                    "file. Open it in your browser instead?"):
                webbrowser.open(w.project_url)
            return
        dest = filedialog.askdirectory(title="Choose download folder")
        if not dest:
            return
        self.app.set_status(f"Downloading {w.name}…")

        def work():
            try:
                path = catalog.download(w, dest, progress=self.app.set_status)
                self.after(0, lambda: messagebox.showinfo("Downloaded", f"Saved to:\n{path}"))
                self.after(0, lambda: self.app.set_status(f"Downloaded → {path}"))
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("Download failed", str(e)))
                self.after(0, lambda: self.app.set_status("Download failed."))

        run_thread(work)


class WordForge(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x720")
        self.minsize(780, 600)
        apply_dark_theme(self)

        # header banner with a subtle geometric pattern (canvas backdrop)
        self.header_canvas = tk.Canvas(self, height=74, highlightthickness=0, bg=SURFACE)
        self.header_canvas.pack(fill="x")
        self.header_canvas.bind(
            "<Configure>",
            lambda e: draw_header_pattern(self.header_canvas, e.width, e.height))
        hcontent = ttk.Frame(self.header_canvas, style="Surface.TFrame")
        self.header_canvas.create_window(SP[6], SP[3], anchor="nw", window=hcontent)
        row = ttk.Frame(hcontent, style="Surface.TFrame")
        row.pack(anchor="w")
        tk.Label(row, text="◆", fg=ACCENT, bg=SURFACE,
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=(0, SP[2]))
        ttk.Label(row, text="WordForge", style="Title.TLabel").pack(side="left")
        ttk.Label(row, text="  wordlist builder", style="Surface.TLabel",
                  foreground=MUTED).pack(side="left", pady=(SP[2], 0))
        ttk.Label(hcontent, text="⚠ " + DISCLAIMER, style="Danger.TLabel",
                  wraplength=880, font=("Segoe UI", 8)).pack(anchor="w", pady=(SP[1], 0))

        # per-profile base wordlist state (the public list each mode builds upon)
        self.bases = {
            "wifi":  {"path": None, "name": "Built-in WPA common"},
            "email": {"path": None, "name": "Built-in common passwords"},
        }
        self.base_vars = {p: tk.StringVar(value=self.bases[p]["name"])
                          for p in self.bases}

        # model bar
        modelbar = ttk.Frame(self, padding=(SP[6], SP[3]))
        modelbar.pack(fill="x")
        ttk.Label(modelbar, text="Model", style="Accent.TLabel").pack(side="left")
        self.model_var = tk.StringVar(value=engine.BUILTIN_LABEL)
        self.model_cb = ttk.Combobox(modelbar, textvariable=self.model_var,
                                     state="readonly", width=38,
                                     values=[engine.BUILTIN_LABEL])
        self.model_cb.pack(side="left", padx=8)
        ttk.Button(modelbar, text="Detect Ollama models",
                   command=self.refresh_models).pack(side="left")
        self.model_note = ttk.Label(modelbar, text="", style="Muted.TLabel")
        self.model_note.pack(side="left", padx=12)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        nb.add(GenTab(nb, "wifi", self), text="  WiFi Wordlist  ")
        nb.add(GenTab(nb, "email", self), text="  Email Wordlist  ")
        self.browse = BrowseTab(nb, self)
        nb.add(self.browse, text="  Browse  ")

        self.status = tk.StringVar(value="Built-in local model ready.")
        ttk.Label(self, textvariable=self.status, style="Status.TLabel",
                  anchor="w").pack(fill="x", side="bottom")

        # warm the built-in model (trains on first use) + probe Ollama
        run_thread(localmodel.get_model)
        self.refresh_models()
        # auto-update Browse + ensure a real base wordlist exists (public lists
        # only — no breach data is ever fetched)
        run_thread(self._launch_update)

    def _launch_update(self):
        # 1) auto-fetch a real base list for each mode (wifi = a WPA list, email =
        #    a passwords list) so generation always appends onto a real wordlist.
        for profile, name in (("wifi", catalog.DEFAULT_WIFI_BASE_NAME),
                              ("email", catalog.DEFAULT_BASE_NAME)):
            if self.bases[profile]["path"]:
                continue
            try:
                path = catalog.ensure_base(name, progress=self.set_status)
            except Exception:  # noqa: BLE001
                path = None
            if path:
                self.bases[profile] = {"path": path, "name": name}
                self.after(0, lambda p=profile, n=name: self.base_vars[p].set(n))
        # train the model on the email/passwords base for realistic samples
        ep = self.bases["email"]["path"]
        if ep:
            try:
                localmodel.reseed_from_words(baselist.load_file(ep))
            except Exception:  # noqa: BLE001
                pass
        # 2) check the curated public lists for newer versions.
        try:
            statuses = catalog.check_updates(progress=self.set_status)
            self.after(0, lambda: self.browse.set_statuses(statuses))
        except Exception:  # noqa: BLE001
            pass
        self.after(0, lambda: self.set_status("Ready."))

    def set_status(self, msg: str):
        self.status.set(msg)
        self.update_idletasks()

    def selected_model(self):
        return self.model_var.get()

    # --- base wordlist (per profile) -------------------------------------- #
    def base_name_for(self, profile: str) -> str:
        return self.bases[profile]["name"]

    def base_words(self, profile: str) -> list[str]:
        path = self.bases[profile]["path"]
        if path:
            try:
                return baselist.load_file(path, max_lines=2_000_000)
            except Exception:  # noqa: BLE001
                pass
        return baselist.base_words(profile)

    def choose_base(self, profile: str):
        path = filedialog.askopenfilename(
            title=f"Choose the base wordlist for {profile} mode "
                  "(downloaded from Browse)",
            filetypes=[("Wordlist", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        name = os.path.basename(path)
        self.bases[profile] = {"path": path, "name": name}
        self.base_vars[profile].set(name + "  (loading…)")
        self.set_status(f"Loading base for {profile}: {name}…")

        def work():
            try:
                words = baselist.load_file(path, max_lines=2_000_000)
                if profile == "email":          # retrain model on passwords base
                    localmodel.reseed_from_words(words[:300000])
                self.after(0, lambda: self.base_vars[profile].set(name))
                self.after(0, lambda: self.set_status(
                    f"{profile} base set to {name} ({len(words)} passwords)."))
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: self.set_status(f"Base load failed: {e}"))
                self.after(0, lambda: self.base_vars[profile].set(name))
        run_thread(work)

    def refresh_models(self):
        def work():
            running, models = engine.ollama_status()

            def apply():
                values = [engine.BUILTIN_LABEL] + models
                self.model_cb.config(values=values)
                if running and models:
                    self.model_note.config(
                        text=f"Ollama online (+{len(models)} model(s))", foreground=OK)
                    self.set_status(f"Built-in model ready · Ollama online "
                                    f"with {len(models)} model(s).")
                elif running:
                    self.model_note.config(text="Ollama online (no models pulled)")
                    self.set_status("Built-in model ready · Ollama online but no models.")
                else:
                    self.model_note.config(text="Ollama not running (optional)")
                    self.set_status("Built-in local model ready. Ollama is optional.")
                # keep current selection valid
                if self.model_var.get() not in values:
                    self.model_var.set(engine.BUILTIN_LABEL)
            self.after(0, apply)
        run_thread(work)


if __name__ == "__main__":
    WordForge().mainloop()
