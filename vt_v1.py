#!/usr/bin/env python3
# vt_scanner_full.py
# Full-featured VirusTotal Desktop Scanner v3.0 (YARA-enabled)
# Run with Python 3.11 (recommended) so yara-python works.

import os
import sys
import hashlib
import requests
import threading
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import tkinter.simpledialog as simpledialog
from concurrent.futures import ThreadPoolExecutor
import json
import csv
import logging
import platform
import time

# Optional imports: yara rules engine and encryption support.
try:
    import yara
except Exception:
    yara = None

try:
    from cryptography.fernet import Fernet
except Exception:
    Fernet = None

if platform.system() == 'Windows':
    try:
        import winreg
    except Exception:
        winreg = None

# --------------------
# Configuration
# --------------------
API_KEY_FILE = 'config.enc'
FERNET_KEY_FILE = 'fernet.key'
CACHE_FILE = 'vt_cache.json'
LOG_FILE = 'vt_scanner.log'
YARA_RULES_DIR = 'yara_rules'

VT_FILE_URL = 'https://www.virustotal.com/api/v3/files'
VT_ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses/'
VT_HASH_URL = 'https://www.virustotal.com/api/v3/files/'

# Configure log file output and format.
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s | %(levelname)s | %(message)s')

# --------------------
# Encryption helpers
# --------------------

def generate_fernet_key():
    """Generate and save the Fernet key for encrypting the API key."""
    if Fernet is None:
        raise RuntimeError('cryptography library not installed. pip install cryptography')
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, 'wb') as f:
        f.write(key)
    logging.info('Generated new Fernet key')
    return key


def encrypt_api_key(api_key: str):
    """Encrypt and persist the API key using Fernet."""
    if Fernet is None:
        raise RuntimeError('cryptography not installed.')
    if not os.path.exists(FERNET_KEY_FILE):
        generate_fernet_key()
    key = open(FERNET_KEY_FILE, 'rb').read()
    f = Fernet(key)
    token = f.encrypt(api_key.encode())
    with open(API_KEY_FILE, 'wb') as f_out:
        f_out.write(token)
    logging.info('Encrypted and saved API key')


def load_api_key():
    """Load the encrypted API key from disk and decrypt it."""
    if Fernet is None:
        raise RuntimeError('cryptography not installed.')
    if not os.path.exists(API_KEY_FILE) or not os.path.exists(FERNET_KEY_FILE):
        return None
    key = open(FERNET_KEY_FILE, 'rb').read()
    f = Fernet(key)
    token = open(API_KEY_FILE, 'rb').read()
    try:
        return f.decrypt(token).decode()
    except Exception as e:
        logging.exception('Failed decrypting API key: %s', e)
        return None

# --------------------
# YARA rule generation & compilation (Option C default balanced pack)
# --------------------

def ensure_default_yara_rules():
    """Ensure the YARA rules directory exists and provide default rules."""
    if not os.path.isdir(YARA_RULES_DIR):
        os.makedirs(YARA_RULES_DIR, exist_ok=True)

    behavior_rule = r'''
rule Suspicious_PE_Structure_C
{
    meta:
        description = "Generic PE structure anomalies"
        author = "Scanner"
    strings:
        $s1 = "This program cannot be run in DOS mode"
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and $s1
}
'''

    rat_rule = r'''
rule RAT_Generic_C
{
    meta:
        description = "Generic RAT behavioral indicator"
        author = "Scanner"
    strings:
        $rat1 = "keylogger" nocase
        $rat2 = "remote access" nocase
        $rat3 = "socket" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($rat*)
}
'''

    trojan_rule = r'''
rule Trojan_Adware_Generic_C
{
    meta:
        description = "Generic Trojan/Adware detection"
        author = "Scanner"
    strings:
        $adv1 = "adware" nocase
        $adv2 = "browser helper" nocase
        $adv3 = "inject" nocase
    condition:
        uint16(0) == 0x5A4D and any of ($adv*)
}
'''

    rules_to_write = {
        'behavior_generic.yar': behavior_rule,
        'rat_generic.yar': rat_rule,
        'trojan_adware_generic.yar': trojan_rule,
    }

    for fname, content in rules_to_write.items():
        fpath = os.path.join(YARA_RULES_DIR, fname)
        if not os.path.exists(fpath):
            with open(fpath, 'w', encoding='utf-8') as fh:
                fh.write(content)


def compile_yara_rules():
    """Compile all YARA rule files if yara-python is available."""
    ensure_default_yara_rules()
    if yara is None:
        logging.info('yara-python not installed; skipping YARA support')
        return None

    rule_files = {}
    for fname in os.listdir(YARA_RULES_DIR):
        if fname.endswith('.yar') or fname.endswith('.yara'):
            rule_files[fname] = os.path.join(YARA_RULES_DIR, fname)

    if not rule_files:
        logging.info('No YARA rule files found in %s', YARA_RULES_DIR)
        return None

    try:
        rules = yara.compile(filepaths=rule_files)
        logging.info('Compiled YARA rules: %s', list(rule_files.keys()))
        return rules
    except Exception as e:
        logging.exception('Failed to compile YARA rules: %s', e)
        return None

# --------------------
# Rate limiter (VirusTotal free: 4 requests/min => 1 request per 15s)
# --------------------
LAST_REQUEST_TIME = 0.0
MIN_INTERVAL = 15.0

def rate_limit():
    """Enforce a minimum delay between VirusTotal API calls."""
    global LAST_REQUEST_TIME
    now = time.time()
    elapsed = now - LAST_REQUEST_TIME
    if elapsed < MIN_INTERVAL:
        to_wait = MIN_INTERVAL - elapsed
        logging.debug('Rate limiter sleeping for %.2f seconds', to_wait)
        time.sleep(to_wait)
    LAST_REQUEST_TIME = time.time()

# --------------------
# VirusTotal helpers
# --------------------

def compute_sha256(filepath):
    """Compute the SHA256 hash for a file."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()


def vt_check_hash(api_key, sha):
    """Check VirusTotal for an existing analysis by file hash."""
    headers = {'x-apikey': api_key}
    try:
        rate_limit()
        r = requests.get(VT_HASH_URL + sha, headers=headers, timeout=30)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return None
        else:
            logging.warning('VT hash lookup returned %s for %s', r.status_code, sha)
            return None
    except Exception as e:
        logging.exception('Exception querying VT hash: %s', e)
        return None


def vt_upload_file(api_key, filepath):
    """Upload a file to VirusTotal for scanning."""
    headers = {'x-apikey': api_key}
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f)}
            rate_limit()
            r = requests.post(VT_FILE_URL, files=files, headers=headers, timeout=120)
        if r.status_code in (200, 201):
            return r.json().get('data', {}).get('id')
        else:
            logging.warning('VT upload failed %s for %s', r.status_code, filepath)
            return None
    except Exception as e:
        logging.exception('Exception uploading to VT: %s', e)
        return None


def vt_get_analysis(api_key, analysis_id):
    """Poll VirusTotal until a file analysis is complete."""
    headers = {'x-apikey': api_key}
    try:
        while True:
            rate_limit()
            r = requests.get(VT_ANALYSIS_URL + analysis_id, headers=headers, timeout=30)
            if r.status_code != 200:
                logging.warning('VT analysis fetch status %s', r.status_code)
                return None
            data = r.json()
            status = data.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                return data
            # else loop (rate limiter already enforces waits)
    except Exception as e:
        logging.exception('Exception getting analysis: %s', e)
        return None


def classify_threat(vt_file_json):
    """Derive a simple threat classification from VT analysis results."""
    try:
        attrs = vt_file_json.get('data', {}).get('attributes', {}) if vt_file_json else {}
        pop = attrs.get('popular_threat_classification') or {}
        if pop:
            cls = pop.get('suggested_threat_label') or pop.get('popular_threat_name')
            if cls:
                return cls
        stats = attrs.get('last_analysis_stats', {}) or {}
        if stats.get('malicious', 0) > 0:
            return 'Malicious'
        if stats.get('suspicious', 0) > 0:
            return 'Suspicious'
        return 'Unknown'
    except Exception:
        return 'Unknown'

# --------------------
# Cache helpers
# --------------------

def load_cache():
    """Load scan results cache from disk."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(c):
    """Save scan results cache to disk."""
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(c, f, indent=2)
    except Exception as e:
        logging.exception('Failed saving cache: %s', e)

# --------------------
# Windows context menu helper (HKEY_CURRENT_USER)
# --------------------

def register_context_menu(exe_path):
    """Register the scanner executable in the Windows Explorer context menu."""
    if platform.system() != 'Windows' or winreg is None:
        raise RuntimeError('Context menu registration only supported on Windows')
    try:
        key_path = r'Software\Classes\*\shell\ScanWithVT'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            winreg.SetValue(k, '', winreg.REG_SZ, 'Scan with VT Scanner')
            cmd_key = key_path + r'\command'
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cmd_key) as c:
                cmd = f'"{exe_path}" "%1"'
                winreg.SetValue(c, '', winreg.REG_SZ, cmd)
        logging.info('Registered context menu for %s', exe_path)
        return True
    except Exception as e:
        logging.exception('Failed to register context menu: %s', e)
        return False

# --------------------
# GUI Application
# --------------------
class VirusTotalScannerApp:
    def __init__(self, root):
        # Initialize the main application window and load state.
        self.root = root
        self.root.title('VT Desktop Scanner v3.0')
        self.root.geometry('1200x700')

        self.api_key = None
        try:
            if Fernet is not None:
                self.api_key = load_api_key()
        except Exception as e:
            logging.exception('Error loading API key: %s', e)

        self.cache = load_cache()
        self.yara_rules = compile_yara_rules()
        self.executor = ThreadPoolExecutor(max_workers=12)

        self.setup_style()
        self.create_widgets()

    def setup_style(self):
        """Apply a dark theme to the Tkinter UI."""
        self.root.configure(bg='#1e1e1e')
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background='#252526', foreground='white', fieldbackground='#252526')
        style.configure('TButton', background='#333333', foreground='white')
        style.configure('TLabel', background='#1e1e1e', foreground='white')

    def create_widgets(self):
        """Construct the buttons, progress bar, and result tree view."""
        top = tk.Frame(self.root, bg='#1e1e1e')
        top.pack(pady=8, anchor='w')

        ttk.Button(top, text='Load API Key', command=self.load_api_key_dialog).pack(side='left', padx=6)
        ttk.Button(top, text='Select Folder', command=self.select_folder).pack(side='left', padx=6)
        ttk.Button(top, text='Select Files', command=self.select_files).pack(side='left', padx=6)
        ttk.Button(top, text='Scan', command=self.start_scan).pack(side='left', padx=6)
        ttk.Button(top, text='Export', command=self.export_results).pack(side='left', padx=6)
        ttk.Button(top, text='Register Context Menu', command=self.register_context_menu_ui).pack(side='left', padx=6)

        self.progress = ttk.Progressbar(self.root, orient='horizontal', length=1000, mode='determinate')
        self.progress.pack(pady=6)

        cols = ('file', 'sha256', 'status')
        self.tree = ttk.Treeview(self.root, columns=cols, show='headings', height=25)
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=380)
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<Double-1>', self.on_item_double)

    def load_api_key_dialog(self):
        """Prompt the user for an API key and encrypt it for future use."""
        if self.api_key:
            messagebox.showinfo('API Key', 'API key already loaded (encrypted on disk)')
            return
        if Fernet is None:
            messagebox.showerror('Missing library', 'cryptography is required to store API key securely.')
            return
        key = simpledialog.askstring('API Key', 'Enter your VirusTotal API key (it will be encrypted on disk)')
        if key:
            encrypt_api_key(key)
            self.api_key = key
            messagebox.showinfo('Saved', 'API key saved encrypted on disk')

    def select_folder(self):
        """Add all files under a selected folder to the scan queue."""
        folder = filedialog.askdirectory()
        if folder:
            for root_dir, _, files in os.walk(folder):
                for f in files:
                    path = os.path.join(root_dir, f)
                    try:
                        sha = compute_sha256(path)
                        self.tree.insert('', 'end', values=(path, sha, 'Pending'))
                    except Exception as e:
                        logging.exception('Error hashing %s: %s', path, e)

    def select_files(self):
        """Add individual selected files to the scan queue."""
        paths = filedialog.askopenfilenames()
        for p in paths:
            try:
                sha = compute_sha256(p)
                self.tree.insert('', 'end', values=(p, sha, 'Pending'))
            except Exception as e:
                logging.exception('Error hashing %s: %s', p, e)

    def start_scan(self):
        """Begin scanning all queued files using background threads."""
        if not self.api_key:
            messagebox.showwarning('API Key', 'Load your VirusTotal API key first')
            return
        items = list(self.tree.get_children())
        total = len(items)
        self.progress['maximum'] = total
        self.progress['value'] = 0

        futures = [self.executor.submit(self.scan_entry, item) for item in items]

        def monitor():
            for f in futures:
                f.result()
                self.progress['value'] += 1
            save_cache(self.cache)
            messagebox.showinfo('Done', 'Scanning complete')

        threading.Thread(target=monitor, daemon=True).start()

    def scan_entry(self, item):
        """Scan a single file entry by checking cache, YARA rules, and VirusTotal."""
        file_path, sha, _ = self.tree.item(item, 'values')
        logging.info('Scanning %s', file_path)

        yara_matches = []
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(file_path)
                yara_matches = [m.rule for m in matches]
            except Exception as e:
                logging.exception('YARA match error: %s', e)

        # Check cache first and then query VirusTotal if needed.
        vt_json = None
        if sha in self.cache and self.cache.get(sha):
            vt_json = self.cache[sha]
            logging.info('Cache hit for %s', sha)
        else:
            vt_json = vt_check_hash(self.api_key, sha)
            if not vt_json:
                analysis_id = vt_upload_file(self.api_key, file_path)
                if analysis_id:
                    vt_json = vt_get_analysis(self.api_key, analysis_id)
            self.cache[sha] = vt_json or {}

        engines = {}
        threat = 'Unknown'
        if vt_json:
            try:
                last = vt_json.get('data', {}).get('attributes', {}).get('last_analysis_results', {}) or {}
                for engine, info in last.items():
                    engines[engine] = {'category': info.get('category'), 'result': info.get('result')}
                threat = classify_threat(vt_json)
            except Exception as e:
                logging.exception('Error parsing VT json: %s', e)

        parts = []
        if yara_matches:
            parts.append('YARA:[' + ','.join(yara_matches) + ']')
        if engines:
            mal = sum(1 for e in engines.values() if e.get('category') == 'malicious')
            susp = sum(1 for e in engines.values() if e.get('category') == 'suspicious')
            parts.append(f'VT M:{mal} S:{susp}')
        parts.append('CLASS:' + threat)
        status = ' | '.join(parts)
        self.tree.item(item, values=(file_path, sha, status))

    def on_item_double(self, event):
        """Show a detail window when the user double-clicks a scan result."""
        iid = self.tree.focus()
        if not iid:
            return
        file_path, sha, status = self.tree.item(iid, 'values')
        detail = tk.Toplevel(self.root)
        detail.title('Details: ' + os.path.basename(file_path))
        detail.geometry('900x600')
        txt = tk.Text(detail, wrap='none')
        txt.pack(fill='both', expand=True)

        vt_json = self.cache.get(sha) or {}
        try:
            engines = vt_json.get('data', {}).get('attributes', {}).get('last_analysis_results', {}) or {}
            txt.insert('end', '--- Engine breakdown ---\n')
            for engine, info in engines.items():
                txt.insert('end', f"{engine}: {info.get('category')} -> {info.get('result')}\n")
        except Exception:
            txt.insert('end', 'No engine data available\n')

        if self.yara_rules:
            try:
                matches = self.yara_rules.match(file_path)
                if matches:
                    txt.insert('end', '\n--- YARA Matches ---\n')
                    for m in matches:
                        txt.insert('end', f'Rule: {m.rule} tags={m.tags} meta={m.meta}\n')
                else:
                    txt.insert('end', '\nNo YARA matches\n')
            except Exception as e:
                txt.insert('end', f'YARA error: {e}\n')
        else:
            txt.insert('end', '\nYARA not enabled\n')

        txt.insert('end', '\n--- VT Raw JSON (truncated) ---\n')
        raw = json.dumps(vt_json, indent=2)
        txt.insert('end', raw[:20000])

    def export_results(self):
        """Export scan results to JSON or CSV."""
        data = [self.tree.item(i, 'values') for i in self.tree.get_children()]
        out = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json'), ('CSV', '*.csv')])
        if not out:
            return
        if out.endswith('.json'):
            with open(out, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        else:
            with open(out, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['File', 'SHA256', 'Status'])
                w.writerows(data)
        messagebox.showinfo('Export', 'Saved')

    def register_context_menu_ui(self):
        """Register a Windows context menu entry for the current scanner executable."""
        if platform.system() != 'Windows':
            messagebox.showwarning('Not supported', 'Context menu registration only supported on Windows')
            return
        exe_path = filedialog.askopenfilename(title='Select the EXE to register for context menu (vt_scanner_full.exe suggested)')
        if not exe_path:
            return
        ok = register_context_menu(exe_path)
        if ok:
            messagebox.showinfo('Registered', 'Context menu registered (HKEY_CURRENT_USER)')

# --------------------
# Main
# --------------------
def main():
    """Start the Tkinter GUI application."""
    root = tk.Tk()
    app = VirusTotalScannerApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
