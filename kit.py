import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import os, sys, threading, time, datetime, hashlib, re, struct, socket
import psutil, csv, json, shutil
from PIL import Image
import wmi, filetype

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ── Font Configuration ───────────────────────────────────────────────
FONT_FAMILY = "Segoe UI"          # Main UI font
MONO_FONT = "Cascadia Code"       # Monospace / data font
MONO_SIZE = 13
HEADING_SIZE = 24
SUBHEAD_SIZE = 14
BODY_SIZE = 13
SMALL_SIZE = 12

ACCENT = "#1f6aa5"
DARK_BG = "#1a1a2e"
CARD_BG = "#16213e"
SIDEBAR_BG = "#0f3460"
TEXT_CLR = "#e0e0e0"
WARN_CLR = "#e94560"
OK_CLR = "#0cca4a"

MODULES = [
    ("📊", "Dashboard"),  ("🗂️", "File Carving"), ("🏷️", "Metadata"),
    ("🔐", "Hash Calc"),  ("🔍", "Hex Viewer"),   ("💾", "USB Analysis"),
    ("🧠", "Memory"),     ("🌐", "Network"),      ("📅", "Timeline"),
    ("🛡️", "Anti-Forensics"), ("📝", "Strings"),
]

FILE_SIGS = {
    "JPEG": (b"\xFF\xD8\xFF", b"\xFF\xD9"), "PNG": (b"\x89PNG\r\n\x1a\n", b"IEND"),
    "PDF": (b"%PDF", b"%%EOF"), "ZIP": (b"PK\x03\x04", None),
    "GIF": (b"GIF8", b"\x00\x3B"), "BMP": (b"BM", None),
    "MP3": (b"\xFF\xFB", None), "AVI": (b"RIFF", None),
}

# ── Main Application ────────────────────────────────────────────────
class DFToolkit(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("⚡ Pro Digital Forensics Toolkit v3.0")
        self.geometry("1280x780")
        self.minsize(1100, 700)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color=SIDEBAR_BG)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        ctk.CTkLabel(self.sidebar, text="⚡ DF Toolkit", font=ctk.CTkFont(family=FONT_FAMILY, size=26, weight="bold"),
                     text_color="#ffffff").pack(padx=20, pady=(25, 5))
        ctk.CTkLabel(self.sidebar, text="v3.0 Professional", font=ctk.CTkFont(family=FONT_FAMILY, size=13),
                     text_color="#8899aa").pack(padx=20, pady=(0, 20))

        self.nav_btns = {}
        for icon, name in MODULES:
            b = ctk.CTkButton(self.sidebar, corner_radius=8, height=40, text=f"  {icon}  {name}",
                              fg_color="transparent", text_color="#c0d0e0",
                              hover_color="#1a4a7a", anchor="w", font=ctk.CTkFont(family=FONT_FAMILY, size=15),
                              command=lambda n=name: self.navigate(n))
            b.pack(fill="x", padx=10, pady=2)
            self.nav_btns[name] = b

        # Status bar
        self.status_frame = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color="#0a0a1a")
        self.status_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(self.status_frame, textvariable=self.status_var, font=(MONO_FONT, 13),
                     text_color="#7799bb").pack(side="left", padx=15)
        self.clock_var = ctk.StringVar()
        ctk.CTkLabel(self.status_frame, textvariable=self.clock_var, font=(MONO_FONT, 13),
                     text_color="#7799bb").pack(side="right", padx=15)
        self._tick_clock()

        # Content area
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        self.active_frame = None
        self.navigate("Dashboard")

    def _tick_clock(self):
        self.clock_var.set(datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def navigate(self, name):
        for n, b in self.nav_btns.items():
            b.configure(fg_color="#1a4a7a" if n == name else "transparent",
                        text_color="#ffffff" if n == name else "#c0d0e0")
        if self.active_frame:
            self.active_frame.destroy()
        self.status_var.set(f"Module: {name}")
        frames = {"Dashboard": DashboardFrame, "File Carving": FileCarvingFrame,
                  "Metadata": MetadataFrame, "Hash Calc": HashCalcFrame,
                  "Hex Viewer": HexViewerFrame, "USB Analysis": USBAnalysisFrame,
                  "Memory": MemoryFrame, "Network": NetworkFrame,
                  "Timeline": TimelineFrame, "Anti-Forensics": AntiForensicsFrame,
                  "Strings": StringExtractorFrame}
        self.active_frame = frames[name](self.content)
        self.active_frame.grid(row=0, column=0, sticky="nsew")


# ── Helpers ──────────────────────────────────────────────────────────
def _card(parent, **kw):
    return ctk.CTkFrame(parent, corner_radius=12, fg_color=CARD_BG, **kw)

def _heading(parent, text):
    ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(family=FONT_FAMILY, size=HEADING_SIZE, weight="bold"),
                 text_color="#ffffff").pack(anchor="w", padx=15, pady=(15, 5))

def _subhead(parent, text):
    ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(family=FONT_FAMILY, size=SUBHEAD_SIZE), text_color="#8899aa").pack(anchor="w", padx=15)

def _make_gauge(parent, label, value, maxv, color=ACCENT):
    f = ctk.CTkFrame(parent, fg_color="transparent")
    f.pack(fill="x", padx=15, pady=6)
    ctk.CTkLabel(f, text=label, width=100, anchor="w", text_color=TEXT_CLR, font=(FONT_FAMILY, BODY_SIZE)).pack(side="left")
    bar = ctk.CTkProgressBar(f, width=200, height=16, progress_color=color)
    bar.pack(side="left", padx=10, expand=True, fill="x")
    bar.set(min(value / maxv, 1.0) if maxv else 0)
    ctk.CTkLabel(f, text=f"{value:.1f}%", width=60, text_color=TEXT_CLR, font=(MONO_FONT, BODY_SIZE)).pack(side="right")
    return bar


# ── 1. Dashboard ─────────────────────────────────────────────────────
class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "📊 System Dashboard")
        _subhead(self, "Live system overview — auto-refreshes every 2 seconds")

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=10)
        for i in range(3): top.grid_columnconfigure(i, weight=1)

        # System info card
        c1 = _card(top); c1.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(c1, text="🖥️ System Info", font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
                     text_color="#ffffff").pack(anchor="w", padx=12, pady=(12,6))
        import platform
        for k, v in [("OS", platform.platform()), ("CPU", platform.processor()[:40]),
                     ("Arch", platform.machine()), ("Python", platform.python_version()),
                     ("Hostname", platform.node())]:
            r = ctk.CTkFrame(c1, fg_color="transparent"); r.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(r, text=f"{k}:", width=90, anchor="w", text_color="#8899aa",
                         font=(MONO_FONT, BODY_SIZE)).pack(side="left")
            ctk.CTkLabel(r, text=v, anchor="w", text_color=TEXT_CLR,
                         font=(MONO_FONT, BODY_SIZE)).pack(side="left")

        # Gauges card
        c2 = _card(top); c2.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(c2, text="📈 Resource Usage", font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
                     text_color="#ffffff").pack(anchor="w", padx=12, pady=(12,6))
        self.cpu_bar = _make_gauge(c2, "CPU", psutil.cpu_percent(), 100, "#e94560")
        self.ram_bar = _make_gauge(c2, "RAM", psutil.virtual_memory().percent, 100, "#f5a623")
        self.disk_bar = _make_gauge(c2, "Disk", psutil.disk_usage('/').percent, 100, "#0cca4a")

        # Quick stats card
        c3 = _card(top); c3.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(c3, text="⚡ Quick Stats", font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
                     text_color="#ffffff").pack(anchor="w", padx=12, pady=(12,6))
        net = psutil.net_io_counters()
        stats = [("Processes", len(psutil.pids())), ("Boot Time",
                 datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%H:%M:%S')),
                 ("Net Sent", f"{net.bytes_sent/(1024**2):.0f} MB"),
                 ("Net Recv", f"{net.bytes_recv/(1024**2):.0f} MB"),
                 ("Connections", len(psutil.net_connections(kind='inet')))]
        for k, v in stats:
            r = ctk.CTkFrame(c3, fg_color="transparent"); r.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(r, text=f"{k}:", width=110, anchor="w", text_color="#8899aa",
                         font=(MONO_FONT, BODY_SIZE)).pack(side="left")
            ctk.CTkLabel(r, text=str(v), anchor="w", text_color=TEXT_CLR,
                         font=(MONO_FONT, BODY_SIZE)).pack(side="left")

        # Process table
        _heading(self, "🔝 Top Processes by Memory")
        self.proc_frame = ctk.CTkScrollableFrame(self, fg_color=CARD_BG, corner_radius=12)
        self.proc_frame.pack(fill="both", expand=True, padx=15, pady=(5,15))
        self._load_procs()
        self._auto_refresh()

    def _load_procs(self):
        for w in self.proc_frame.winfo_children(): w.destroy()
        hdr = ctk.CTkFrame(self.proc_frame, fg_color="#0d1b30"); hdr.pack(fill="x", pady=(0,4))
        for t, w in [("PID",65),("Name",190),("CPU%",75),("Mem MB",85),("Status",85)]:
            ctk.CTkLabel(hdr, text=t, width=w, anchor="w", font=ctk.CTkFont(family=FONT_FAMILY, size=BODY_SIZE, weight="bold"),
                         text_color="#aabbcc").pack(side="left", padx=4)
        procs = sorted(psutil.process_iter(['pid','name','cpu_percent','memory_info','status']),
                       key=lambda p: p.info.get('memory_info').rss if p.info.get('memory_info') else 0,
                       reverse=True)
        for p in procs[:40]:
            try:
                inf = p.info; mem = inf['memory_info'].rss/(1024*1024) if inf['memory_info'] else 0
                row = ctk.CTkFrame(self.proc_frame, fg_color="transparent", height=24)
                row.pack(fill="x", pady=0)
                c = WARN_CLR if mem > 500 else TEXT_CLR
                for v, w in [(inf['pid'],60),(inf['name'],180),(f"{inf['cpu_percent']:.0f}",70),
                             (f"{mem:.1f}",80),(inf['status'],80)]:
                    ctk.CTkLabel(row, text=str(v), width=w, anchor="w", text_color=c,
                                 font=(MONO_FONT, MONO_SIZE)).pack(side="left", padx=4)
            except: pass

    def _auto_refresh(self):
        try:
            cpu = psutil.cpu_percent(); self.cpu_bar.set(cpu/100)
            self.ram_bar.set(psutil.virtual_memory().percent/100)
            self.disk_bar.set(psutil.disk_usage('/').percent/100)
        except: pass
        self.after(2000, self._auto_refresh)


# ── 2. File Carving ──────────────────────────────────────────────────
class FileCarvingFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🗂️ File Carving — Signature-Based Recovery")
        _subhead(self, "Scan disk images or raw files for embedded file signatures")
        self.path_var = ctk.StringVar()
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=10)
        ctk.CTkEntry(row, textvariable=self.path_var, placeholder_text="Source file path...",
                     width=500).pack(side="left", padx=(0,8))
        ctk.CTkButton(row, text="Browse", width=80, command=self._browse).pack(side="left", padx=4)
        ctk.CTkButton(row, text="▶  Start Carving", width=140, fg_color=OK_CLR, hover_color="#0aa03d",
                      text_color="#000", command=self._start).pack(side="left", padx=4)

        sf = _card(self); sf.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(sf, text="Signatures:", text_color="#aabbcc").pack(side="left", padx=12, pady=10)
        self.sig_vars = {}
        for name in FILE_SIGS:
            v = ctk.BooleanVar(value=True); self.sig_vars[name] = v
            ctk.CTkCheckBox(sf, text=name, variable=v, width=70).pack(side="left", padx=6, pady=10)

        self.progress = ctk.CTkProgressBar(self, height=6); self.progress.pack(fill="x", padx=15, pady=4)
        self.progress.set(0)
        self.log = ctk.CTkTextbox(self, font=(MONO_FONT, MONO_SIZE), fg_color=CARD_BG, corner_radius=12)
        self.log.pack(fill="both", expand=True, padx=15, pady=(4,15))

    def _browse(self):
        p = filedialog.askopenfilename(); 
        if p: self.path_var.set(p)

    def _start(self):
        src = self.path_var.get()
        if not src or not os.path.exists(src):
            self._log("❌ Source file not found."); return
        threading.Thread(target=self._carve, args=(src,), daemon=True).start()

    def _carve(self, src):
        out = os.path.join(os.path.dirname(src), "carved_output"); os.makedirs(out, exist_ok=True)
        targets = {n: s for n, s in FILE_SIGS.items() if self.sig_vars[n].get()}
        self._log(f"📂 Scanning: {src}")
        try:
            fsize = os.path.getsize(src); chunk = 64*1024*1024; total_found = 0
            with open(src, "rb") as f:
                offset = 0
                while True:
                    data = f.read(chunk)
                    if not data: break
                    for name, (header, footer) in targets.items():
                        pos = 0
                        while True:
                            idx = data.find(header, pos)
                            if idx == -1: break
                            end = min(idx + 5*1024*1024, len(data))
                            if footer:
                                fi = data.find(footer, idx+len(header))
                                if fi != -1: end = fi + len(footer)
                            fname = os.path.join(out, f"carved_{total_found}.{name.lower()}")
                            with open(fname, "wb") as o: o.write(data[idx:end])
                            total_found += 1; pos = idx + 1
                            self._log(f"  ✅ {name} @ offset {offset+idx:#010x}")
                    offset += len(data)
                    if fsize > 0: self.progress.set(min(offset / fsize, 1.0))
            self._log(f"\n🎉 Done! {total_found} files carved → {out}")
            self.progress.set(1.0)
        except Exception as e: self._log(f"❌ Error: {e}")

    def _log(self, m): self.log.insert("end", m+"\n"); self.log.see("end")


# ── 3. Metadata ──────────────────────────────────────────────────────
class MetadataFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🏷️ Metadata Extraction")
        _subhead(self, "File properties, EXIF data, hashes, and NTFS attributes")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=10)
        ctk.CTkButton(row, text="Select File", command=self._browse).pack(side="left")
        self.lbl = ctk.CTkLabel(row, text="No file selected", text_color="#8899aa")
        self.lbl.pack(side="left", padx=10)
        self.box = ctk.CTkTextbox(self, font=(MONO_FONT, MONO_SIZE), fg_color=CARD_BG, corner_radius=12)
        self.box.pack(fill="both", expand=True, padx=15, pady=(4,15))

    def _browse(self):
        p = filedialog.askopenfilename()
        if p: self.lbl.configure(text=os.path.basename(p)); self._extract(p)

    def _extract(self, p):
        self.box.delete("1.0","end")
        try:
            s = os.stat(p); k = filetype.guess(p)
            self.box.insert("end", f"{'='*50}\n  FILE METADATA REPORT\n{'='*50}\n\n")
            self.box.insert("end", f"Path:     {p}\nSize:     {s.st_size:,} bytes\n")
            self.box.insert("end", f"Type:     {k.mime if k else 'Unknown'}\n")
            self.box.insert("end", f"Created:  {datetime.datetime.fromtimestamp(s.st_ctime)}\n")
            self.box.insert("end", f"Modified: {datetime.datetime.fromtimestamp(s.st_mtime)}\n")
            self.box.insert("end", f"Accessed: {datetime.datetime.fromtimestamp(s.st_atime)}\n\n")
            # Hashes
            self.box.insert("end", "── Hashes ──\n")
            for algo in ["md5","sha1","sha256"]:
                h = hashlib.new(algo)
                with open(p,"rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
                self.box.insert("end", f"{algo.upper():8s}: {h.hexdigest()}\n")
            # EXIF
            if p.lower().endswith(('.jpg','.jpeg','.png','.tiff')):
                try:
                    import exifread
                    self.box.insert("end", "\n── EXIF Data ──\n")
                    with open(p,'rb') as f:
                        tags = exifread.process_file(f)
                        for t in sorted(tags.keys()):
                            if t not in ('JPEGThumbnail','TIFFThumbnail','EXIF MakerNote'):
                                self.box.insert("end", f"{t}: {tags[t]}\n")
                except: pass
        except Exception as e: self.box.insert("end", f"Error: {e}\n")


# ── 4. Hash Calculator ──────────────────────────────────────────────
class HashCalcFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🔐 Hash Calculator")
        _subhead(self, "Compute and verify file integrity hashes")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=10)
        self.path_var = ctk.StringVar()
        ctk.CTkEntry(row, textvariable=self.path_var, placeholder_text="File path...",
                     width=450).pack(side="left", padx=(0,8))
        ctk.CTkButton(row, text="Browse", width=80, command=self._browse).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Compute", width=100, fg_color=OK_CLR, text_color="#000",
                      command=self._compute).pack(side="left", padx=4)

        self.progress = ctk.CTkProgressBar(self, height=6); self.progress.pack(fill="x", padx=15, pady=6)
        self.progress.set(0)

        card = _card(self); card.pack(fill="x", padx=15, pady=5)
        self.hash_labels = {}
        for algo in ["MD5","SHA-1","SHA-256"]:
            r = ctk.CTkFrame(card, fg_color="transparent"); r.pack(fill="x", padx=12, pady=6)
            ctk.CTkLabel(r, text=f"{algo}:", width=80, anchor="w", text_color="#aabbcc",
                         font=ctk.CTkFont(family=FONT_FAMILY, size=15, weight="bold")).pack(side="left")
            lbl = ctk.CTkLabel(r, text="—", anchor="w", text_color=TEXT_CLR, font=(MONO_FONT, MONO_SIZE))
            lbl.pack(side="left", expand=True, fill="x")
            self.hash_labels[algo] = lbl
            ctk.CTkButton(r, text="📋", width=30, height=26,
                          command=lambda a=algo: self._copy(a)).pack(side="right")

        # Compare section
        cmp = _card(self); cmp.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(cmp, text="Verify Against Known Hash:", text_color="#aabbcc",
                     font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=12, pady=(10,4))
        cr = ctk.CTkFrame(cmp, fg_color="transparent"); cr.pack(fill="x", padx=12, pady=(0,10))
        self.cmp_entry = ctk.CTkEntry(cr, placeholder_text="Paste known hash here...", width=500)
        self.cmp_entry.pack(side="left", padx=(0,8))
        ctk.CTkButton(cr, text="Compare", width=80, command=self._compare).pack(side="left")
        self.cmp_result = ctk.CTkLabel(cmp, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=15))
        self.cmp_result.pack(padx=12, pady=(0,10))

    def _browse(self):
        p = filedialog.askopenfilename()
        if p: self.path_var.set(p)

    def _compute(self):
        p = self.path_var.get()
        if not p or not os.path.exists(p): return
        threading.Thread(target=self._calc, args=(p,), daemon=True).start()

    def _calc(self, p):
        algos = {"MD5": hashlib.md5(), "SHA-1": hashlib.sha1(), "SHA-256": hashlib.sha256()}
        sz = os.path.getsize(p); done = 0
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for h in algos.values(): h.update(chunk)
                done += len(chunk)
                if sz: self.progress.set(done/sz)
        for name, h in algos.items():
            self.hash_labels[name].configure(text=h.hexdigest())
        self.progress.set(1.0)

    def _copy(self, algo):
        t = self.hash_labels[algo].cget("text")
        if t and t != "—": self.clipboard_clear(); self.clipboard_append(t)

    def _compare(self):
        known = self.cmp_entry.get().strip().lower()
        if not known: return
        for _, lbl in self.hash_labels.items():
            if lbl.cget("text").lower() == known:
                self.cmp_result.configure(text="✅ MATCH — File integrity verified!", text_color=OK_CLR); return
        self.cmp_result.configure(text="❌ NO MATCH — Hash mismatch detected!", text_color=WARN_CLR)


# ── 5. Hex Viewer ────────────────────────────────────────────────────
class HexViewerFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🔍 Hex Viewer")
        _subhead(self, "Inspect raw file bytes with hex + ASCII view")
        self.file_data = b""; self.offset = 0; self.bytes_per_page = 512
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=10)
        ctk.CTkButton(row, text="Open File", command=self._open).pack(side="left", padx=(0,8))
        self.info = ctk.CTkLabel(row, text="No file loaded", text_color="#8899aa")
        self.info.pack(side="left", padx=10)

        nav = ctk.CTkFrame(self, fg_color="transparent"); nav.pack(fill="x", padx=15, pady=4)
        ctk.CTkButton(nav, text="◀ Prev", width=80, command=self._prev).pack(side="left", padx=4)
        ctk.CTkButton(nav, text="Next ▶", width=80, command=self._next).pack(side="left", padx=4)
        self.off_lbl = ctk.CTkLabel(nav, text="Offset: 0x00000000", font=(MONO_FONT, MONO_SIZE), text_color=TEXT_CLR)
        self.off_lbl.pack(side="left", padx=20)

        sr = ctk.CTkFrame(self, fg_color="transparent"); sr.pack(fill="x", padx=15, pady=4)
        self.search_var = ctk.StringVar()
        ctk.CTkEntry(sr, textvariable=self.search_var, placeholder_text="Search hex (e.g. FF D8 FF)...",
                     width=300).pack(side="left", padx=(0,8))
        ctk.CTkButton(sr, text="Find", width=60, command=self._find).pack(side="left")

        self.hex_box = ctk.CTkTextbox(self, font=(MONO_FONT, 14), fg_color=CARD_BG, corner_radius=12)
        self.hex_box.pack(fill="both", expand=True, padx=15, pady=(4,15))

    def _open(self):
        p = filedialog.askopenfilename()
        if not p: return
        with open(p,"rb") as f: self.file_data = f.read()
        self.offset = 0; self.info.configure(text=f"{os.path.basename(p)} ({len(self.file_data):,} bytes)")
        self._render()

    def _prev(self):
        self.offset = max(0, self.offset - self.bytes_per_page); self._render()

    def _next(self):
        self.offset = min(len(self.file_data)-1, self.offset + self.bytes_per_page); self._render()

    def _find(self):
        try:
            pattern = bytes.fromhex(self.search_var.get().replace(" ",""))
            idx = self.file_data.find(pattern, self.offset+1)
            if idx >= 0: self.offset = (idx // 16) * 16; self._render()
        except: pass

    def _render(self):
        self.hex_box.delete("1.0","end"); self.off_lbl.configure(text=f"Offset: {self.offset:#010x}")
        chunk = self.file_data[self.offset:self.offset+self.bytes_per_page]
        lines = []
        for i in range(0, len(chunk), 16):
            row = chunk[i:i+16]
            addr = f"{self.offset+i:08X}"
            hexpart = " ".join(f"{b:02X}" for b in row).ljust(48)
            asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"{addr}  {hexpart}  |{asciipart}|")
        self.hex_box.insert("end", "\n".join(lines))


# ── 6. USB Analysis ──────────────────────────────────────────────────
class USBAnalysisFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "💾 USB / Drive Analysis")
        _subhead(self, "Detect connected drives, partitions, and USB devices via WMI")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=10)
        ctk.CTkButton(row, text="🔄 Scan Drives", command=self._scan).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Export JSON", command=self._export).pack(side="left", padx=4)
        self.box = ctk.CTkTextbox(self, font=(MONO_FONT, MONO_SIZE), fg_color=CARD_BG, corner_radius=12)
        self.box.pack(fill="both", expand=True, padx=15, pady=(4,15))
        self.drives_data = []
        self._scan()

    def _scan(self):
        self.box.delete("1.0","end"); self.drives_data = []
        try:
            c = wmi.WMI()
            self.box.insert("end", "╔══════════════════════════════════════════╗\n")
            self.box.insert("end", "║       PHYSICAL DISK DRIVES               ║\n")
            self.box.insert("end", "╚══════════════════════════════════════════╝\n\n")
            for d in c.Win32_DiskDrive():
                sz = int(d.Size)/(1024**3) if d.Size else 0
                info = {"DeviceID": d.DeviceID, "Model": d.Model, "Interface": d.InterfaceType,
                        "Size_GB": f"{sz:.2f}", "Serial": str(d.SerialNumber).strip(), "Status": d.Status}
                self.drives_data.append(info)
                for k, v in info.items():
                    self.box.insert("end", f"  {k:12s}: {v}\n")
                self.box.insert("end", "  " + "─"*38 + "\n")
            self.box.insert("end", "\n╔══════════════════════════════════════════╗\n")
            self.box.insert("end", "║       LOGICAL DISK PARTITIONS            ║\n")
            self.box.insert("end", "╚══════════════════════════════════════════╝\n\n")
            for p in c.Win32_LogicalDisk():
                sz = int(p.Size)/(1024**3) if p.Size else 0
                free = int(p.FreeSpace)/(1024**3) if p.FreeSpace else 0
                self.box.insert("end", f"  Drive {p.DeviceID}  [{p.FileSystem or '?'}]  "
                                       f"{sz:.1f} GB total, {free:.1f} GB free\n")
        except Exception as e: self.box.insert("end", f"Error: {e}\n")

    def _export(self):
        p = filedialog.asksaveasfilename(defaultextension=".json")
        if p:
            with open(p,"w") as f: json.dump(self.drives_data, f, indent=2)


# ── 7. Memory Forensics ─────────────────────────────────────────────
class MemoryFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🧠 Memory Forensics — Live Process Analysis")
        ctrl = ctk.CTkFrame(self, fg_color="transparent"); ctrl.pack(fill="x", padx=15, pady=8)
        ctk.CTkButton(ctrl, text="🔄 Refresh", command=self._load).pack(side="left", padx=4)
        self.filter_var = ctk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self._load())
        ctk.CTkEntry(ctrl, textvariable=self.filter_var, placeholder_text="Filter by name...",
                     width=200).pack(side="left", padx=8)
        self.sort_var = ctk.StringVar(value="Memory ↓")
        ctk.CTkOptionMenu(ctrl, values=["Memory ↓","CPU ↓","PID ↓","Name ↑"], variable=self.sort_var,
                          command=lambda _: self._load(), width=120).pack(side="left", padx=4)
        self.count_lbl = ctk.CTkLabel(ctrl, text="", text_color="#8899aa")
        self.count_lbl.pack(side="right", padx=10)
        self.tree = ctk.CTkScrollableFrame(self, fg_color=CARD_BG, corner_radius=12)
        self.tree.pack(fill="both", expand=True, padx=15, pady=(4,15))
        self._load()

    def _load(self):
        for w in self.tree.winfo_children(): w.destroy()
        hdr = ctk.CTkFrame(self.tree, fg_color="#0d1b30"); hdr.pack(fill="x", pady=(0,4))
        for t, w in [("PID",60),("Name",180),("CPU%",60),("Mem MB",80),("Status",75),("User",160)]:
            ctk.CTkLabel(hdr, text=t, width=w, anchor="w", font=ctk.CTkFont(family=FONT_FAMILY, size=BODY_SIZE, weight="bold"),
                         text_color="#aabbcc").pack(side="left", padx=3)
        filt = self.filter_var.get().lower()
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_info','status','username']):
            try:
                i = p.info
                if filt and filt not in (i['name'] or '').lower(): continue
                mem = i['memory_info'].rss/(1024*1024) if i['memory_info'] else 0
                procs.append((i['pid'], i['name'] or '?', i['cpu_percent'] or 0, mem,
                              i['status'] or '?', i['username'] or '?'))
            except: pass
        sk = self.sort_var.get()
        if "Memory" in sk: procs.sort(key=lambda x: x[3], reverse=True)
        elif "CPU" in sk: procs.sort(key=lambda x: x[2], reverse=True)
        elif "PID" in sk: procs.sort(key=lambda x: x[0])
        else: procs.sort(key=lambda x: x[1].lower())
        self.count_lbl.configure(text=f"{len(procs)} processes")
        for pid, nm, cpu, mem, st, usr in procs[:80]:
            row = ctk.CTkFrame(self.tree, fg_color="transparent", height=22); row.pack(fill="x")
            c = WARN_CLR if mem > 500 or cpu > 50 else TEXT_CLR
            for v, w in [(pid,60),(nm,180),(f"{cpu:.0f}",60),(f"{mem:.1f}",80),(st,75),(usr,160)]:
                ctk.CTkLabel(row, text=str(v), width=w, anchor="w", text_color=c,
                             font=(MONO_FONT, MONO_SIZE)).pack(side="left", padx=3)


# ── 8. Network Monitor ──────────────────────────────────────────────
class NetworkFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🌐 Network Monitor")
        _subhead(self, "Live network connections and per-process breakdown")
        ctrl = ctk.CTkFrame(self, fg_color="transparent"); ctrl.pack(fill="x", padx=15, pady=8)
        ctk.CTkButton(ctrl, text="🔄 Refresh", command=self._load).pack(side="left", padx=4)
        ctk.CTkButton(ctrl, text="Export CSV", command=self._export).pack(side="left", padx=4)
        self.filter_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(ctrl, values=["All","ESTABLISHED","LISTEN","TIME_WAIT","CLOSE_WAIT"],
                          variable=self.filter_var, command=lambda _: self._load(), width=140).pack(side="left", padx=8)
        self.count_lbl = ctk.CTkLabel(ctrl, text="", text_color="#8899aa")
        self.count_lbl.pack(side="right", padx=10)

        # IO stats
        sf = _card(self); sf.pack(fill="x", padx=15, pady=5)
        net = psutil.net_io_counters()
        for k, v in [("Bytes Sent", f"{net.bytes_sent/(1024**2):.1f} MB"),
                     ("Bytes Recv", f"{net.bytes_recv/(1024**2):.1f} MB"),
                     ("Packets Sent", f"{net.packets_sent:,}"), ("Packets Recv", f"{net.packets_recv:,}"),
                     ("Errors In", str(net.errin)), ("Errors Out", str(net.errout))]:
            ctk.CTkLabel(sf, text=f"{k}: {v}", text_color=TEXT_CLR, font=(MONO_FONT, SMALL_SIZE)).pack(side="left", padx=12, pady=8)

        self.tree = ctk.CTkScrollableFrame(self, fg_color=CARD_BG, corner_radius=12)
        self.tree.pack(fill="both", expand=True, padx=15, pady=(4,15))
        self.conn_data = []
        self._load()

    def _load(self):
        for w in self.tree.winfo_children(): w.destroy()
        hdr = ctk.CTkFrame(self.tree, fg_color="#0d1b30"); hdr.pack(fill="x", pady=(0,4))
        for t, w in [("PID",55),("Process",150),("Local",180),("Remote",180),("Status",105),("Type",55)]:
            ctk.CTkLabel(hdr, text=t, width=w, anchor="w", font=ctk.CTkFont(family=FONT_FAMILY, size=BODY_SIZE, weight="bold"),
                         text_color="#aabbcc").pack(side="left", padx=3)
        filt = self.filter_var.get(); self.conn_data = []
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                st = c.status
                if filt != "All" and st != filt: continue
                pid = c.pid or 0
                try: pname = psutil.Process(pid).name() if pid else "—"
                except: pname = "?"
                la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
                ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                self.conn_data.append({"PID":pid,"Process":pname,"Local":la,"Remote":ra,"Status":st,"Type":proto})
                row = ctk.CTkFrame(self.tree, fg_color="transparent", height=22); row.pack(fill="x")
                clr = OK_CLR if st == "ESTABLISHED" else WARN_CLR if "WAIT" in st else TEXT_CLR
                for v, w in [(pid,55),(pname,150),(la,180),(ra,180),(st,105),(proto,55)]:
                    ctk.CTkLabel(row, text=str(v), width=w, anchor="w", text_color=clr,
                                 font=(MONO_FONT, MONO_SIZE)).pack(side="left", padx=3)
        except Exception as e:
            ctk.CTkLabel(self.tree, text=f"Error: {e}", text_color=WARN_CLR).pack()
        self.count_lbl.configure(text=f"{len(self.conn_data)} connections")

    def _export(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv")
        if p and self.conn_data:
            with open(p,"w",newline="") as f:
                w = csv.DictWriter(f, fieldnames=self.conn_data[0].keys()); w.writeheader(); w.writerows(self.conn_data)


# ── 9. Timeline ──────────────────────────────────────────────────────
class TimelineFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "📅 Timeline Reconstruction")
        _subhead(self, "Reconstruct file activity timelines from any directory")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=8)
        ctk.CTkButton(row, text="Select Directory", command=self._browse).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Export CSV", command=self._export).pack(side="left", padx=4)
        self.lbl = ctk.CTkLabel(row, text="No directory selected", text_color="#8899aa")
        self.lbl.pack(side="left", padx=10)
        self.progress = ctk.CTkProgressBar(self, height=6); self.progress.pack(fill="x", padx=15, pady=4)
        self.progress.set(0)
        self.box = ctk.CTkTextbox(self, font=(MONO_FONT, MONO_SIZE), fg_color=CARD_BG, corner_radius=12, wrap="none")
        self.box.pack(fill="both", expand=True, padx=15, pady=(4,15))
        self.timeline_data = []

    def _browse(self):
        p = filedialog.askdirectory()
        if p: self.lbl.configure(text=p); threading.Thread(target=self._scan, args=(p,), daemon=True).start()

    def _scan(self, path):
        self.box.delete("1.0","end"); self.timeline_data = []
        self.box.insert("end", f"Scanning {path}...\n\n")
        files = []; total = 0
        for r, ds, fs in os.walk(path): total += len(fs)
        done = 0
        for r, ds, fs in os.walk(path):
            for fn in fs:
                fp = os.path.join(r, fn)
                try:
                    s = os.stat(fp)
                    for label, ts in [("MOD", s.st_mtime), ("ACC", s.st_atime), ("CRE", s.st_ctime)]:
                        files.append((ts, label, fp, s.st_size))
                except: pass
                done += 1
                if total: self.progress.set(done/total)
        files.sort(key=lambda x: x[0], reverse=True)
        self.box.insert("end", f"{'Timestamp':<22} {'Type':<6} {'Size':>10}  {'Path'}\n")
        self.box.insert("end", "─"*90 + "\n")
        colors = {"MOD":"🟢","ACC":"🔵","CRE":"🟡"}
        for ts, lbl, fp, sz in files[:2000]:
            dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            self.box.insert("end", f"{dt:<22} {colors.get(lbl,'')}{lbl:<5} {sz:>10,}  {fp}\n")
            self.timeline_data.append({"Timestamp":dt,"Type":lbl,"Size":sz,"Path":fp})
        self.progress.set(1.0)
        self.box.insert("end", f"\n✅ {len(files)} events from {done} files.")

    def _export(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv")
        if p and self.timeline_data:
            with open(p,"w",newline="") as f:
                w = csv.DictWriter(f, fieldnames=["Timestamp","Type","Size","Path"]); w.writeheader(); w.writerows(self.timeline_data)


# ── 10. Anti-Forensics ──────────────────────────────────────────────
class AntiForensicsFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "🛡️ Anti-Forensics Detection")
        _subhead(self, "Detect tampering: extension mismatch, hidden files, timestamp anomalies, entropy")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=8)
        ctk.CTkButton(row, text="Scan Directory", command=self._browse).pack(side="left", padx=4)
        self.lbl = ctk.CTkLabel(row, text="No directory selected", text_color="#8899aa")
        self.lbl.pack(side="left", padx=10)
        self.progress = ctk.CTkProgressBar(self, height=6); self.progress.pack(fill="x", padx=15, pady=4)
        self.progress.set(0)
        self.box = ctk.CTkTextbox(self, font=(MONO_FONT, MONO_SIZE), fg_color=CARD_BG, corner_radius=12)
        self.box.pack(fill="both", expand=True, padx=15, pady=(4,15))

    def _browse(self):
        p = filedialog.askdirectory()
        if p: self.lbl.configure(text=p); threading.Thread(target=self._scan, args=(p,), daemon=True).start()

    def _scan(self, path):
        self.box.delete("1.0","end"); issues = 0
        self.box.insert("end", f"🔎 Scanning {path} for anomalies...\n\n")
        allfiles = []
        for r, ds, fs in os.walk(path):
            for fn in fs: allfiles.append(os.path.join(r, fn))
        for i, fp in enumerate(allfiles):
            if len(allfiles): self.progress.set((i+1)/len(allfiles))
            try:
                s = os.stat(fp)
                # Extension mismatch
                kind = filetype.guess(fp)
                if kind:
                    ext = os.path.splitext(fp)[1].lower().replace(".","")
                    if ext and ext != kind.extension:
                        self.box.insert("end", f"⚠️  [EXT MISMATCH] {fp}\n    Content={kind.extension}, Extension={ext}\n\n")
                        issues += 1
                # Hidden file
                if sys.platform == 'win32':
                    if s.st_file_attributes & 2:
                        self.box.insert("end", f"👁️  [HIDDEN FILE] {fp}\n\n"); issues += 1
                # Timestamp anomaly
                if s.st_ctime > s.st_mtime + 1:
                    self.box.insert("end", f"🕐  [TIME STOMP] {fp}\n    Created ({datetime.datetime.fromtimestamp(s.st_ctime)}) > "
                                           f"Modified ({datetime.datetime.fromtimestamp(s.st_mtime)})\n\n")
                    issues += 1
                # Entropy check (high entropy = encrypted/compressed)
                if s.st_size > 0 and s.st_size < 50*1024*1024:
                    with open(fp,"rb") as f: data = f.read(min(s.st_size, 1024*1024))
                    if data:
                        import math
                        freq = [0]*256
                        for b in data: freq[b] += 1
                        ent = -sum((c/len(data))*math.log2(c/len(data)) for c in freq if c > 0)
                        if ent > 7.9:
                            self.box.insert("end", f"🔥  [HIGH ENTROPY] {fp}  (entropy={ent:.3f})\n"
                                                   f"    Possibly encrypted or packed content\n\n")
                            issues += 1
            except: pass
        self.progress.set(1.0)
        self.box.insert("end", f"\n{'='*50}\n✅ Scan complete. {issues} anomalies detected in {len(allfiles)} files.\n")


# ── 11. String Extractor ────────────────────────────────────────────
class StringExtractorFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        _heading(self, "📝 String Extractor")
        _subhead(self, "Extract printable ASCII/Unicode strings from binary files")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=15, pady=8)
        self.path_var = ctk.StringVar()
        ctk.CTkEntry(row, textvariable=self.path_var, placeholder_text="Binary file...",
                     width=400).pack(side="left", padx=(0,8))
        ctk.CTkButton(row, text="Browse", width=80, command=self._browse).pack(side="left", padx=4)
        ctk.CTkLabel(row, text="Min length:", text_color="#aabbcc").pack(side="left", padx=(12,4))
        self.minlen = ctk.StringVar(value="6")
        ctk.CTkEntry(row, textvariable=self.minlen, width=50).pack(side="left")
        ctk.CTkButton(row, text="▶ Extract", fg_color=OK_CLR, text_color="#000",
                      command=self._extract).pack(side="left", padx=8)
        ctk.CTkButton(row, text="Export", command=self._export).pack(side="left", padx=4)

        self.progress = ctk.CTkProgressBar(self, height=6); self.progress.pack(fill="x", padx=15, pady=4)
        self.progress.set(0)
        self.box = ctk.CTkTextbox(self, font=(MONO_FONT, MONO_SIZE), fg_color=CARD_BG, corner_radius=12)
        self.box.pack(fill="both", expand=True, padx=15, pady=(4,15))
        self.strings_found = []

    def _browse(self):
        p = filedialog.askopenfilename()
        if p: self.path_var.set(p)

    def _extract(self):
        p = self.path_var.get()
        if not p or not os.path.exists(p): return
        threading.Thread(target=self._run, args=(p,), daemon=True).start()

    def _run(self, p):
        self.box.delete("1.0","end"); self.strings_found = []
        ml = int(self.minlen.get() or 6)
        sz = os.path.getsize(p); done = 0
        pattern = re.compile(rb'[\x20-\x7E]{%d,}' % ml)
        self.box.insert("end", f"Extracting strings (min {ml} chars) from {os.path.basename(p)}...\n\n")
        with open(p,"rb") as f:
            while True:
                chunk = f.read(1024*1024)
                if not chunk: break
                for m in pattern.finditer(chunk):
                    s = m.group().decode('ascii', errors='ignore')
                    off = done + m.start()
                    self.strings_found.append((off, s))
                    self.box.insert("end", f"{off:#010x}  {s}\n")
                done += len(chunk)
                if sz: self.progress.set(done/sz)
        self.progress.set(1.0)
        self.box.insert("end", f"\n✅ Found {len(self.strings_found)} strings.\n")

    def _export(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if p and self.strings_found:
            with open(p,"w") as f:
                for off, s in self.strings_found: f.write(f"{off:#010x}  {s}\n")


if __name__ == "__main__":
    app = DFToolkit()
    app.mainloop()