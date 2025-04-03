# -*- coding: utf-8 -*-
# Put encoding declaration at the top

V=71
import urllib.request
import urllib.parse
from urllib.parse import quote
import os
import sys # Import sys early
import base64
import random
import subprocess
import json
import time
import re
import socket
import datetime # Keep standard datetime import
import shutil # For file operations like backup
import textwrap # For formatting help text

# ---> Dependency Installation and Import Section <---

# Function to check and install pip if missing (basic check)
def ensure_pip():
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # print("pip is available.")
        return True
    except subprocess.CalledProcessError:
        print("pip not found. Attempting to install...")
        try:
            # Try using ensurepip
            subprocess.check_call([sys.executable, '-m', 'ensurepip', '--upgrade'])
            print("pip installed successfully using ensurepip.")
            return True
        except Exception as e1:
            print(f"ensurepip failed: {e1}")
            # Try getting pip script (less reliable, might need manual intervention)
            print("Trying to download get-pip.py...")
            try:
                get_pip_url = "https://bootstrap.pypa.io/get-pip.py"
                response = requests.get(get_pip_url) # Need requests here, chicken-egg problem?
                if response.status_code == 200:
                    with open("get-pip.py", "w") as f:
                        f.write(response.text)
                    subprocess.check_call([sys.executable, "get-pip.py"])
                    print("pip installed successfully using get-pip.py.")
                    os.remove("get-pip.py")
                    return True
                else:
                    print(f"Failed to download get-pip.py (status: {response.status_code}).")
            except Exception as e2:
                print(f"Failed to install pip using get-pip.py: {e2}")
        print("\033[91mCould not install pip automatically. Please install it manually.\033[0m")
        return False
    except FileNotFoundError:
        print("\033[91mPython executable not found? Cannot check for pip.\033[0m")
        return False


# Function to install a package using pip
def install_package(package_name, import_name=None):
    if not import_name:
        import_name = package_name
    try:
        __import__(import_name)
        # print(f"{package_name} already installed.") # Optional confirmation
    except ImportError:
        print(f"{package_name} module not found. Installing now...")
        if not ensure_pip(): # Check if pip exists first
            return False # Cannot install without pip

        # Try installing the package
        install_command = [sys.executable, '-m', 'pip', 'install', package_name]
        print(f"Running: {' '.join(install_command)}") # Show command being run
        pip_return_code = subprocess.call(install_command)

        if pip_return_code == 0:
            print(f"{package_name} installed successfully via pip.")
            # Verify import after install
            try:
                __import__(import_name)
                return True
            except ImportError:
                 print(f"\033[91mImport failed even after installing {package_name}. Check installation.\033[0m")
                 return False
        else:
            print(f"\033[91mpip install failed for {package_name} (return code: {pip_return_code}). Trying alternative names or methods...\033[0m")
             # Add alternative install methods here if needed (e.g., cryptography complex install)
             # For cryptography:
            if package_name == 'cryptography':
                 print("Attempting complex cryptography install (may require build tools)...")
                 # Termux specific first (more likely to work there)
                 if 'com.termux' in os.environ.get('PREFIX', ''):
                     if subprocess.call(['pkg', 'install', 'python-cryptography', '-y']) == 0:
                          print("Cryptography installed via pkg.")
                          try: __import__(import_name); return True
                          except ImportError: print("Import still failed after pkg install."); return False
                 # Generic build attempt
                 os.environ['CFLAGS'] = '-Wno-implicit-function-declaration' # Common flag needed
                 pip_build_code = subprocess.call([sys.executable, '-m', 'pip', 'install', package_name, '--no-binary', ':all:'])
                 if pip_build_code == 0:
                     print("Cryptography installed via pip build.")
                     try: __import__(import_name); return True
                     except ImportError: print("Import still failed after pip build."); return False
                 else:
                     print("\033[91mAll install attempts for cryptography failed.\033[0m")
                     return False

            # For qrcode[pil]
            elif package_name == 'qrcode[pil]':
                 print("Trying 'pip install qrcode' and 'pip install Pillow' separately...")
                 pip_code_qr = subprocess.call([sys.executable, '-m', 'pip', 'install', 'qrcode'])
                 pip_code_pil = subprocess.call([sys.executable, '-m', 'pip', 'install', 'Pillow'])
                 if pip_code_qr == 0 and pip_code_pil == 0:
                      print("qrcode and Pillow installed separately.")
                      try: __import__(import_name); import PIL; return True # Check both
                      except ImportError: print("Import failed after separate installs."); return False
                 else:
                      print("\033[91mSeparate install failed for qrcode/Pillow.\033[0m")
                      return False

            else: # No specific alternative for this package
                 print(f"\033[91mCould not install {package_name}. Please install it manually.\033[0m")
                 return False
    return True # Return True if already installed or installed successfully

# Install required packages
print("Checking dependencies...")
required_packages = {
    'requests': 'requests',
    'rich': 'rich',
    'retrying': 'retrying',
    'icmplib': 'icmplib',
    'alive_progress': 'alive_progress',
    'qrcode[pil]': 'qrcode', # Special package name for installation
    'cryptography': 'cryptography' # Needed for API 2
}

dependencies_ok = True
for pkg_install_name, pkg_import_name in required_packages.items():
    if not install_package(pkg_install_name, pkg_import_name):
        # Handle critical failures - e.g., exit if requests or rich fail
        if pkg_import_name in ['requests', 'rich', 'icmplib']:
            print(f"\033[91mCritical dependency '{pkg_import_name}' failed to install. Exiting.\033[0m")
            sys.exit(1)
        elif pkg_import_name == 'cryptography':
            print(f"\033[93mWarning: Optional dependency '{pkg_import_name}' failed to install. API 2 will be unavailable.\033[0m")
            # We can continue, but API 2 functionality will fail later if chosen
        elif pkg_import_name == 'qrcode':
             print(f"\033[93mWarning: Optional dependency '{pkg_import_name}' failed to install. QR Code generation will be unavailable.\033[0m")
             # Set a flag or variable to disable QR code generation later
             _qrcode_available = False
        else:
            print(f"\033[93mWarning: Dependency '{pkg_import_name}' failed to install. Some features might not work.\033[0m")
            # Allow script to continue for non-critical dependencies

# Conditional imports after installation checks
try: import requests
except ImportError: dependencies_ok = False # Should have exited earlier if critical

try:
    import rich
    from rich.console import Console
    from rich.prompt import Prompt
    from rich import print as rprint
    from rich.table import Table
    from rich.panel import Panel # For better display
    from rich.syntax import Syntax # For JSON highlighting
except ImportError: dependencies_ok = False # Should have exited

try:
    import retrying
    from retrying import retry
except ImportError:
    # Define dummy retry decorator if module failed but wasn't critical exit
    def retry(*args, **kwargs):
        def decorator(func): return func
        return decorator
    print("[yellow]Retrying module unavailable. Network operations might be less reliable.[/yellow]")


try: from concurrent.futures import ThreadPoolExecutor, as_completed
except ImportError: print("[red]concurrent.futures not found (standard library?). Exiting.[/red]"); sys.exit(1)

try: from requests.exceptions import ConnectionError, Timeout, RequestException
except ImportError: dependencies_ok = False

try: from icmplib import ping as pinging
except ImportError: dependencies_ok = False # Should have exited

try: from alive_progress import alive_bar
except ImportError:
     print("[yellow]alive_progress unavailable. Progress bars will be basic text.[/yellow]")
     # Define dummy alive_bar
     def alive_bar(total, *args, **kwargs):
         print("Progress bar unavailable. Continuing...")
         class DummyBar:
             def __init__(self, total): self.total = total; self.count = 0
             def __call__(self): self.count += 1; print(f"Progress: {self.count}/{self.total}", end='\r')
             def __enter__(self): return self
             def __exit__(self, *args): print("\nDone.")
         return DummyBar(total)

try:
    import qrcode
    import qrcode.image.pil # Check PIL factory
    _qrcode_available = True
except ImportError:
    # This handles the case where install_package reported success but import still fails
    if '_qrcode_available' not in locals() or _qrcode_available: # Avoid double warning
         print(f"\033[93mWarning: qrcode module import failed. QR Code generation will be unavailable.\033[0m")
    _qrcode_available = False


# Cryptography check for API 2 flag
_cryptography_available = False
try:
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    _cryptography_available = True
except ImportError:
    if 'cryptography' in required_packages: # Only warn if it was supposed to be installed
        print(f"\033[93mWarning: cryptography module import failed. API 2 will be unavailable.\033[0m")


if not dependencies_ok:
     print("\033[91mCritical dependencies failed to load properly. Exiting.\033[0m")
     sys.exit(1)

# ---> End Dependency Section <---


# Global variables
api='' # Stores user choice ('1' or '2') for Cloudflare key API
ports = [854, 864, 878, 880, 890, 891, 894, 908, 928, 934, 943, 945, 956, 968, 987, 988, 1002, 1010, 1018, 1026, 1034, 1058, 1074, 1080, 1180, 1387, 1843, 2371, 2408, 2506, 3137, 3476, 3581, 4177, 4198, 4235, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8854, 8886] # Expanded common CF ports
console = Console()
wire_config_temp='' # Used for building multi-config Sing-Box JSON string
wire_c=1 # Counter for multi-config naming
wire_p=0 # Flag used in multi-config generation (state tracking)
results=[] # IPv4 scan results
resultss=[] # IPv6 scan results
best_result=None # Holds the best IP found [ip_str, port_int] or None
WoW_v2='' # Used for building multi-config V2Ray JSON string
isIran='' # User choice ('1' Iran, '2' Germany) for WoW/Sing-Box mode
max_workers_number=500 # Default worker threads for scanning
do_you_save='2' # Default 'No' for saving scan results
which='' # Format for saving results ('1' bpb, '2' vahid, '3' detailed)
ping_range='300' # Default max ping (ms) for saving results
need_port='1' # Default 'Yes' to include port when saving results
polrn_block='2' # Default 'No' for blocking porn sites in configs
how_many = 1 # Default number of configs for subscriptions

# --- Utility Functions ---

def gt_resolution():
    try: return os.get_terminal_size().columns
    except OSError: return 80

def info():
    console.clear()
    table = Table(show_header=True, title="Info", header_style="bold blue")
    table.add_column("Creator", width=15)
    table.add_column("Contact", justify="right")
    table.add_row("arshiacomplus", "1 - Telegram")
    table.add_row("arshiacomplus", "2 - GitHub")
    console.print(table)
    rprint('\nEnter a Number\n')
    options2 = {"1": "Open Telegram Channel", "2": "Open GitHub Page", "0": "Back to Main Menu"}
    for key, value in options2.items(): rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    whats2 = Prompt.ask("Choose an option", choices=list(options2.keys()), default="0")
    open_cmd = None
    if sys.platform.startswith('linux') or sys.platform == 'darwin': open_cmd = 'xdg-open' if sys.platform.startswith('linux') else 'open'
    elif sys.platform == 'win32': open_cmd = 'start'
    elif 'com.termux' in os.environ.get('PREFIX', ''): open_cmd = 'termux-open-url'

    url = None
    if whats2 == '1': url = 'https://t.me/arshia_mod_fun'
    elif whats2 == '2': url = 'https://github.com/arshiacomplus/'

    if url and open_cmd:
        try: subprocess.run([open_cmd, url], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, FileNotFoundError) as e: rprint(f"[red]Could not open URL: {e}[/red]")
    elif url: rprint("[yellow]Cannot determine command to open URL on this system.[/yellow]")


def check_ipv6():
    ipv4, ipv6 = "[red]Unavailable[/red]", "[red]Unavailable[/red]"
    timeout = 8 # Reduced timeout
    try:
        response_v4 = requests.get('https://v4.ident.me', timeout=timeout) # Use alternative service
        if response_v4.status_code == 200 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', response_v4.text.strip()):
            ipv4 = "[green]Available[/green]"
    except RequestException: pass # Ignore connection errors etc.

    try:
        response_v6 = requests.get('https://v6.ident.me', timeout=timeout) # Use alternative service
        if response_v6.status_code == 200 and ':' in response_v6.text.strip():
            ipv6 = "[green]Available[/green]"
    except RequestException: pass
    return ipv4, ipv6

def input_p(prompt_text, options, default_choice="1"):
    console.clear()
    options_with_exit = options.copy()
    options_with_exit["0"] = "Exit Script"
    rprint(f"[bold cyan]{prompt_text}[/bold cyan]\n")
    for key, value in options_with_exit.items(): rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    valid_keys = list(options_with_exit.keys())
    if default_choice not in valid_keys: default_choice = valid_keys[0] if valid_keys else None
    whats = Prompt.ask("\nChoose an option", choices=valid_keys, default=default_choice)
    if whats == '0':
        gojo_goodbye_animation()
        console.print("[bold magenta]Exiting script... Goodbye![/bold magenta]")
        sys.exit()
    return whats

def urlencode(string):
    if string is None: return None
    return urllib.parse.quote(str(string), safe='a-zA-Z0-9.~_-')

# --- Cloudflare Account/Key Functions ---

@retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, (ConnectionError, urllib.error.URLError, socket.timeout, Timeout)))
def fetch_cf_api(url):
    try:
        response = requests.get(url, timeout=20) # Slightly shorter timeout
        response.raise_for_status()
        return response.text
    except RequestException as e:
        raise ConnectionError(f"Failed to connect to {url}: {e}") # Reraise standard error for retry

def fetch_config_from_api_v1(): # API 1 (Custom API)
    try:
        response = fetch_cf_api("http://s9.serv00.com:1074/arshiacomplus/api/wirekey")
        b = response.splitlines()
        config = {}
        if len(b) >= 4:
            try:
                config['Address'] = b[0].split(":", 1)[1].strip()
                config['PrivateKey'] = b[1].split(":", 1)[1].strip()
                reserved_str = b[2].split(":", 1)[1].strip()
                config['Reserved'] = [int(item) for item in reserved_str.split()]
                config['PublicKey'] = b[3].split(":", 1)[1].strip() # PEER public key
                if ':' in config['Address'] and '/' not in config['Address']: config['Address'] += "/128"
                return config
            except (IndexError, ValueError) as e: rprint(f"[red]Error parsing API 1 response: {e}[/red]"); return None
        else: rprint(f"[red]Incomplete response from API 1 (got {len(b)} lines).[/red]"); return None
    except (ConnectionError, Exception) as e: rprint(f"[red]Error fetching/parsing API 1: {e}[/red]"); return None

# --- API 2 Functions (Cloudflare Client API) ---
def byte_to_base64(myb): return base64.b64encode(myb).decode('utf-8')

def generate_private_key_bytes():
    if not _cryptography_available: return None
    key = os.urandom(32)
    key_list = list(key)
    key_list[0] &= 248; key_list[31] &= 127; key_list[31] |= 64
    return bytes(key_list)

def generate_public_key_bytes(private_key_bytes):
    if not _cryptography_available or not private_key_bytes: return None
    private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = private_key.public_key()
    return public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

@retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, (ConnectionError, Timeout)))
def register_key_on_cf_api(pub_key_b64): # Renamed inner function
    url = 'https://api.cloudflareclient.com/v0a4005/reg'
    install_id = base64.b64encode(os.urandom(12)).decode('utf-8')
    fcm_token = install_id + "_fcm"
    body = {
        "key": pub_key_b64, "install_id": install_id, "fcm_token": fcm_token,
        "warp_enabled": True,
        "tos": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
        "type": "Android", "model": "PC", "locale": "en_US"
    }
    headers = { 'Content-Type': 'application/json; charset=UTF-8', 'Host': 'api.cloudflareclient.com', 'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip', 'User-Agent': 'okhttp/3.12.1'}
    try:
        response = requests.post(url, data=json.dumps(body), headers=headers, timeout=25)
        response.raise_for_status()
        return response
    except RequestException as e:
        # Optional: Log full error details for debugging
        # rprint(f"[yellow]CF API registration failed: Status={e.response.status_code if e.response else 'N/A'}, Body={e.response.text[:200] if e.response else 'N/A'}[/yellow]")
        raise ConnectionError(f"Failed to register key with CF API: {e}")


def bind_keys_dynamically(): # API 2 Main function
    if not _cryptography_available:
        rprint("[red]Cannot use API 2: Cryptography library is not available.[/red]")
        return None

    priv_bytes = generate_private_key_bytes()
    if not priv_bytes: rprint("[red]Failed to generate private key.[/red]"); return None

    pub_bytes = generate_public_key_bytes(priv_bytes)
    if not pub_bytes: rprint("[red]Failed to generate public key.[/red]"); return None

    priv_string_b64 = byte_to_base64(priv_bytes)
    pub_string_b64 = byte_to_base64(pub_bytes) # This is OUR public key

    rprint("[cyan]Registering generated key with Cloudflare API...[/cyan]")
    try:
        result = register_key_on_cf_api(pub_string_b64) # Register OUR public key
    except ConnectionError as e:
         rprint(f"[red]{e}[/red]"); return None

    if result and result.status_code == 200:
        try:
            cf_data = result.json()
            account = cf_data.get('account', {})
            config = cf_data.get('config', {})
            peers = config.get('peers', [])
            interface = config.get('interface', {})
            addresses = interface.get('addresses', {})
            ipv6_address = addresses.get('v6')
            account_id_b64 = account.get('account_id')

            if not peers: rprint("[red]No peer info in CF API response.[/red]"); return None
            peer_public_key = peers[0].get('public_key') # This is the SERVER/PEER public key

            if ipv6_address and peer_public_key and account_id_b64:
                 try:
                     cid_bytes = base64.b64decode(account_id_b64)
                     reserved = list(cid_bytes)
                 except (base64.binascii.Error, TypeError): reserved = [0,0,0] # Fallback

                 # Return dict: {'Address': OurIPv6, 'PrivateKey': OurPrivKey, 'Reserved': OurReserved, 'PublicKey': PeerPubKey}
                 return {
                     'Address': f"{ipv6_address}/128",
                     'PrivateKey': priv_string_b64, # Our private key
                     'Reserved': reserved,
                     'PublicKey': peer_public_key   # Peer's public key
                 }
            else: rprint("[red]Missing required fields in CF API response.[/red]"); return None
        except (json.JSONDecodeError, KeyError, IndexError) as e: rprint(f"[red]Error parsing CF API response: {e}[/red]"); return None
    else: rprint("[red]Failed to register key with CF API (non-200 status).[/red]"); return None

# --- Combined Key Fetcher ---
def free_cloudflare_account():
    global api
    if not api:
        default_api = '1' # Default to custom API unless crypto is available
        api_options = {'1': 'Custom API (api.serv00.com)'}
        if _cryptography_available:
             api_options['2'] = 'Cloudflare Client API (Generates New Keys)'
             default_api = '2' # Default to CF API if crypto works
        else:
             rprint("[yellow]Cryptography library missing, Cloudflare API (Option 2) disabled.[/yellow]")

        api = input_p('Which API to use for keys?', api_options, default_choice=default_api)

    if api == '2' and _cryptography_available:
        rprint("[cyan]Using Cloudflare Client API (API 2)...[/cyan]")
        config_dict = bind_keys_dynamically()
        if config_dict: return config_dict
        else: rprint("[red]Failed to get keys using API 2. Try API 1 or check errors.[/red]"); return None
    else: # Default to API 1 or if API 2 chosen but unavailable
        if api == '2' and not _cryptography_available:
             rprint("[yellow]API 2 selected but unavailable, falling back to API 1.[/yellow]")
        rprint("[cyan]Using Custom API (API 1)...[/cyan]")
        config_dict = fetch_config_from_api_v1()
        if config_dict: return config_dict
        else: rprint("[red]Failed to get keys using API 1.[/red]"); return None

# --- QR Code Generation ---
def generate_qr_code(data):
    if not _qrcode_available:
        rprint("[yellow]QR Code generation skipped (qrcode library not available).[/yellow]")
        return
    if data:
        try:
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=1, border=2)
            qr.add_data(data)
            qr.make(fit=True)
            console.print("\n[bold]QR Code:[/bold]")
            qr.print_tty() # Print to terminal
            console.print("[dim](Scan the QR code above with your client)[/dim]")
        except Exception as e:
             rprint(f"[red]Could not generate/print QR code: {e}[/red]")
             rprint("[yellow]The URL/Link is still available above.[/yellow]")
    else: rprint("[red]No data provided for QR code.[/red]")


# --- Bashupload Function ---
@retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, (ConnectionError, Timeout)))
def post_to_bashupload(config_data_str): # Expects string data
    files = {'file': ('config_sub.json', config_data_str)}
    try:
        response = requests.post('https://bashupload.com/', files=files, timeout=45)
        response.raise_for_status()
        return response
    except RequestException as e:
        rprint(f"[yellow]Bashupload request failed: {e}[/yellow]")
        raise ConnectionError("Failed to connect to Bashupload")

# ---> CHANGE: Modify upload_to_bashupload to return the link <---
def upload_to_bashupload(config_data_str):
    rprint("[cyan]Uploading configuration to Bashupload...[/cyan]")
    download_link_with_query = None # Initialize link to None
    try:
        response = post_to_bashupload(config_data_str)
        if response and response.ok:
            match = re.search(r'(https?://bashupload\.com/\w+)', response.text) # Simpler regex
            if match:
                 download_link_base = match.group(0)
                 download_link_with_query = download_link_base + "?download=1"
                 console.print(f'[bold green]Bashupload Download Link:[/bold green] {download_link_with_query}') # Still print it
            else:
                 console.print("[red]Could not find download link in Bashupload response.[/red]")
        else:
            status = response.status_code if response is not None else "N/A"
            console.print(f"[red]Failed to upload to Bashupload. Status: {status}[/red]", style="bold red")
    except (ConnectionError, Exception) as e:
        console.print(f"[red]An error occurred during Bashupload: {e}[/red]", style="bold red")

    return download_link_with_query # Return the link (or None if failed)
# ---> END CHANGE <---

# --- IP Scanning Functions ---
def create_ip_range(start_ip, end_ip):
    try:
        start = list(map(int, start_ip.split('.'))); end = list(map(int, end_ip.split('.')))
        if len(start) != 4 or len(end) != 4: raise ValueError("Invalid IP format")
    except ValueError: rprint(f"[red]Invalid IP format: {start_ip} - {end_ip}[/red]"); return []
    ip_range = []; temp = start[:]
    while True:
        ip_str = '.'.join(map(str, temp)); ip_range.append(ip_str)
        if temp == end: break
        temp[3] += 1
        for i in range(3, 0, -1):
            if temp[i] == 256: temp[i] = 0; temp[i-1] += 1
            else: break
        # Safety break if somehow overshoot (shouldn't happen)
        if temp[0]>end[0] or (temp[0]==end[0] and temp[1]>end[1]) or \
           (temp[0]==end[0] and temp[1]==end[1] and temp[2]>end[2]) or \
           (temp[0]==end[0] and temp[1]==end[1] and temp[2]==end[2] and temp[3]>end[3]): break
    return ip_range

def scan_ip_port_v4(ip, shared_results_list):
    port = random.choice(ports)
    try:
        icmp = pinging(ip, count=2, interval=0.5, timeout=2, privileged=False)
        if icmp.is_alive:
            shared_results_list.append((ip, port, float(icmp.avg_rtt) if icmp.avg_rtt is not None else 9999.0, icmp.packet_loss, float(icmp.jitter) if icmp.jitter is not None else 9999.0))
    except Exception: pass # Suppress ping errors

def generate_ipv6():
    prefix = f"2606:4700:d{random.randint(0, 1)}:"
    suffix = ':'.join(f'{random.randint(0, 65535):x}' for _ in range(5))
    return prefix + suffix

def ping_ip_v6(ip, shared_results_list):
    port = random.choice(ports) # Use the main expanded ports list
    try:
        icmp = pinging(ip, count=2, interval=0.5, timeout=2, privileged=False, family=6)
        if icmp.is_alive:
            shared_results_list.append((ip, port, float(icmp.avg_rtt) if icmp.avg_rtt is not None else 9999.0, icmp.packet_loss, float(icmp.jitter) if icmp.jitter is not None else 9999.0))
    except Exception: pass

def process_and_display_results(results_list, ip_version=4):
    global best_result, save_result, do_you_save, which, ping_range, need_port
    if not results_list: console.print("[yellow]No responsive IPs found.[/yellow]"); best_result = None; return None
    extended_results = []
    for ip, port, ping, loss_rate, jitter in results_list:
        ping = min(ping, 9998.0); jitter = min(jitter, 9998.0)
        loss_penalty = (loss_rate * 100) * 10; ping_score = ping * 0.6; jitter_score = jitter * 0.4
        combined_score = ping_score + jitter_score + loss_penalty
        extended_results.append((ip, port, ping, loss_rate * 100, jitter, combined_score))
    sorted_results = sorted(extended_results, key=lambda x: x[5])
    console.clear()
    table = Table(show_header=True, title=f"IPv{ip_version} Scan Results (Top {min(len(sorted_results), 20)})", header_style="bold blue")
    table.add_column("IP", style="dim cyan", width=40 if ip_version == 6 else 15)
    table.add_column("Port", justify="right"); table.add_column("Ping (ms)", justify="right")
    table.add_column("Loss (%)", justify="right"); table.add_column("Jitter (ms)", justify="right")
    table.add_column("Score", justify="right")
    save_candidates = []
    for ip, port, ping, loss_display, jitter, score in sorted_results[:20]:
        loss_style = "red" if loss_display > 0 else "green"
        table.add_row(ip, str(port), f"{ping:.2f}", f"[{loss_style}]{loss_display:.1f}%[/{loss_style}]", f"{jitter:.2f}", f"{score:.2f}")
        if do_you_save == '1' and loss_display == 0.0:
            try: ping_limit = float(ping_range) if ping_range.replace('.', '', 1).isdigit() else 300.0
            except ValueError: ping_limit = 300.0
            if ping <= ping_limit: save_candidates.append((ip, port, ping, loss_display, jitter))
    console.print(table)
    best_result_current_scan = None
    if sorted_results:
        best_ip, best_port, best_ping, best_loss, best_jitter, best_score = sorted_results[0]
        if best_loss == 0.0:
             console.print(f"\n[bold green]Best Result (Score: {best_score:.2f}):[/bold green] [cyan]{best_ip}:{best_port}[/cyan] (Ping: {best_ping:.2f} ms, Loss: {best_loss:.1f}%, Jitter: {best_jitter:.2f} ms)")
             best_result_current_scan = [best_ip, best_port]
        else:
             console.print(f"\n[yellow]Best found IP has packet loss ({best_loss:.1f}%):[/yellow] [cyan]{best_ip}:{best_port}[/cyan]")
             console.print("[yellow]Consider re-scanning or manually choosing IP for configs.[/yellow]")
    else: console.print("\n[red]No suitable IPs found after filtering.[/red]")
    best_result = best_result_current_scan # Update global best_result

    if do_you_save == '1' and save_candidates:
        save_path = '/storage/emulated/0/result.csv'
        if 'com.termux' in os.environ.get('PREFIX', ''):
            if os.system('termux-setup-storage > /dev/null 2>&1') != 0: # Suppress output
                 rprint("[red]Failed storage permissions. Cannot save.[/red]")
                 return best_result
        try: os.makedirs(os.path.dirname(save_path), exist_ok=True)
        except OSError as e: rprint(f"[red]Error creating directory: {e}[/red]"); return best_result
        try:
            with open(save_path, "w") as f:
                output_lines = []
                for ip, port, ping, loss, jitter in save_candidates:
                    line_base = f"{ip}:{port}" if need_port == '1' else ip
                    if which == '3': line = f"{line_base} | ping: {ping:.2f} loss: {loss:.1f}% jitter: {jitter:.2f}"
                    else: line = line_base
                    output_lines.append(line)
                if which == '1': f.write(",".join(output_lines))
                else: f.write("\n".join(output_lines)) # Vahid or Detailed
                f.write("\n")
            console.print(f"[bold green]Results saved to:[/bold green] {save_path}")
        except IOError as e: console.print(f"[red]Error writing results: {e}[/red]")
        except Exception as e: console.print(f"[red]Unexpected error saving: {e}[/red]")
    return best_result


def run_scan(scanner_func, results_list, num_ips, max_workers, title):
    """Generic function to run scanning tasks with progress."""
    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = []
    with console.status(f"[bold green]Submitting {title} tasks...[/]") as status:
        if title == "IPv6":
            ips_to_ping = {generate_ipv6() for _ in range(num_ips)}
            futures = [executor.submit(scanner_func, ip, results_list) for ip in ips_to_ping]
        else: # IPv4 from ranges
            cf_ranges = [("188.114.96.0", "188.114.99.255"), ("162.159.192.0", "162.159.195.255"), ("104.16.0.0", "104.31.255.255")]
            all_ips_to_scan = []
            for start_ip, end_ip in cf_ranges: all_ips_to_scan.extend(create_ip_range(start_ip, end_ip))
            if not all_ips_to_scan: rprint("[red]No IPv4s generated.[/red]"); return False
            num_ips = len(all_ips_to_scan) # Update actual number
            futures = [executor.submit(scanner_func, ip, results_list) for ip in all_ips_to_scan]
        status.update(f"[bold green]Scanning {len(futures)} {title} addresses...[/]")

    none = gt_resolution(); bar_size = max(10, min(none - 40, 50))
    rprint(f"[magenta]Scanning {len(futures)} IPs using {max_workers} workers...[/magenta]")
    try:
        if 'alive_bar' in globals() and callable(alive_bar):
            with alive_bar(total=len(futures), length=bar_size, title=title, bar='smooth', spinner='dots') as bar:
                for future in as_completed(futures):
                    try: future.result()
                    except Exception: pass
                    bar()
        else: # Fallback progress
            for i, future in enumerate(as_completed(futures)):
                try: future.result()
                except Exception: pass
                print(f"Progress: {i+1}/{len(futures)}", end='\r')
            print()
    except KeyboardInterrupt: console.print("\n[bold yellow]Scan interrupted.[/bold yellow]"); executor.shutdown(wait=False, cancel_futures=True); return False
    except Exception as e: rprint(f'\n[bold red]Error during {title} scan: {e}[/bold red]')
    finally: executor.shutdown(wait=True)
    return True

def main_scan_v6():
    global resultss; resultss = []; console.clear(); rprint("[bold blue]Starting IPv6 Scan...[/bold blue]")
    if run_scan(ping_ip_v6, resultss, num_ips=1500, max_workers=800, title="IPv6"): # Increased default IPs
        return process_and_display_results(resultss, ip_version=6)
    return None

def main_scan_v4():
    global results, max_workers_number; results = []; console.clear(); rprint("[bold blue]Starting IPv4 Scan...[/bold blue]")
    scan_power = max_workers_number if max_workers_number > 0 else 500
    if run_scan(scan_ip_port_v4, results, num_ips=0, max_workers=scan_power, title="IPv4"): # num_ips is determined inside run_scan for v4
         return process_and_display_results(results, ip_version=4)
    return None

def main_scan_wrapper():
    global ping_range, do_you_save, which, need_port, max_workers_number, best_result
    best_result = None
    do_you_save = input_p('Save scan results to file?', {"1": 'Yes', "2": "No"}, '2')
    if do_you_save == '1':
        if 'com.termux' in os.environ.get('PREFIX', ''): os.system('termux-setup-storage > /dev/null 2>&1')
        which = input_p('Select output format for saving:', {'1': 'BPB (Comma)', '2': 'Vahid (Newline)', '3': 'Detailed'}, '2')
        if which != '4': need_port = input_p('Include port?', {'1': 'Yes', '2': 'No'}, '1')
        ping_range_input = Prompt.ask('\nMax ping (ms) for saving [def: 300, "n"]', default='n')
        ping_range = '300' if ping_range_input.lower() == 'n' or not ping_range_input.replace('.', '', 1).isdigit() else ping_range_input
        rprint(f"[cyan]Saving IPs with ping <= {ping_range}ms, 0% loss.[/cyan]")
    which_v = input_p('Choose IP version to scan:', {"1": 'IPv4', "2": 'IPv6'}, '1')
    if which_v == "1":
        cpu_speed = input_p('Scan intensity:', {"1": "Faster (More workers)", "2": "Slower (Fewer)"}, '1')
        max_workers_number = 1000 if cpu_speed == "1" else 400
        return main_scan_v4()
    elif which_v == "2": return main_scan_v6()
    else: rprint("[red]Invalid selection.[/red]"); return None


# --- Configuration Generation Functions ---

def generate_v2ray_wow_config(keys1, keys2, best_ip_info, remark_base="arshiacomplus", add_noise=False):
     if not best_ip_info or len(best_ip_info) < 2: rprint("[red]WoW: Best IP missing.[/red]"); return None
     best_ip, best_port = best_ip_info
     dns_hosts = {"geosite:category-ads-all": "127.0.0.1", "geosite:category-ads-ir": "127.0.0.1"}
     if polrn_block == '1': dns_hosts["geosite:category-porn"] = "127.0.0.1"
     dns_servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", {"address": "8.8.8.8", "domains": ["geosite:category-ir", "domain:.ir"], "port": 53}]
     inbounds = [ {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}, "tag": "socks-in"}, {"port": 10809, "protocol": "http", "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}, "tag": "http-in"}, {"listen": "127.0.0.1", "port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"} ]
     outbounds = []
     # Warp-Out (Primary)
     warp_out_settings = { "secretKey": keys1['PrivateKey'], "address": ["172.16.0.2/32", keys1['Address']], "peers": [{"publicKey": keys1['PublicKey'], "endpoint": f"{best_ip}:{best_port}"}], "mtu": 1280, "reserved": keys1['Reserved'] }
     if add_noise: warp_out_settings.update({"keepAlive": 10, "wnoise": "quic", "wnoisecount": "10-15", "wpayloadsize": "1-8", "wnoisedelay": "1-3"})
     outbounds.append({"protocol": "wireguard", "tag": "warp-out", "settings": warp_out_settings, "streamSettings": {"sockopt": {"dialerProxy": "warp-ir"}} if isIran == '2' else None})
     # Warp-IR (Secondary - only if Germany mode)
     if isIran == '2':
         warp_ir_settings = { "secretKey": keys2['PrivateKey'], "address": ["172.16.0.2/32", keys2['Address']], "peers": [{"publicKey": keys2['PublicKey'], "endpoint": "162.159.192.1:2408"}], "mtu": 1280, "reserved": keys2['Reserved'] } # Fixed endpoint for IR leg
         if add_noise: warp_ir_settings.update({"keepAlive": 10, "wnoise": "quic", "wnoisecount": "10-15", "wpayloadsize": "1-8", "wnoisedelay": "1-3"})
         outbounds.append({"protocol": "wireguard", "tag": "warp-ir", "settings": warp_ir_settings})
     # Standard utility outbounds
     outbounds.extend([ {"protocol": "dns", "tag": "dns-out"}, {"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"} ])
     # Routing Rules
     routing_rules = [ {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out"}, {"type": "field", "ip": ["8.8.8.8"], "port": "53", "outboundTag": "direct"}, {"type": "field", "domain": ["geosite:category-ir", "domain:.ir"], "outboundTag": "direct"}, {"type": "field", "ip": ["geoip:ir", "geoip:private"], "outboundTag": "direct"}, {"type": "field", "domain": list(dns_hosts.keys()), "outboundTag": "block"}, {"type": "field", "network": "tcp,udp", "outboundTag": "warp-out"} ]
     v2ray_config = { "log": {"loglevel": "warning"}, "dns": {"hosts": dns_hosts, "servers": dns_servers, "tag": "dns"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules}, "policy": {"levels": {"8": {"connIdle": 300, "handshake": 4}}, "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}}, "stats": {}, "remarks": f"Tel= {remark_base} - WoW ({'IR' if isIran=='1' else 'DE'}){' Noise' if add_noise else ''}" }
     try: return json.dumps(v2ray_config, indent=2)
     except TypeError as e: rprint(f"[red]Error serializing WoW JSON: {e}[/red]"); return None


def generate_multiple_v2ray_wow(how_many_configs, current_index, best_ip_info, add_noise=False):
     global WoW_v2
     keys1 = free_cloudflare_account(); time.sleep(0.5) # Shorter delay
     keys2 = free_cloudflare_account()
     if not keys1 or not keys2: rprint(f"[red]Skip WoW {current_index+1}: key fetch failed.[/red]"); return
     config_json_str = generate_v2ray_wow_config(keys1, keys2, best_ip_info, add_noise=add_noise)
     if config_json_str:
         WoW_v2 += config_json_str
         if current_index < how_many_configs - 1: WoW_v2 += ',\n'
     else: rprint(f"[red]Skip WoW {current_index+1}: JSON generation failed.[/red]")


def generate_singbox_warp_config(keys1, keys2, best_ip_info, use_noise=False, remark_base="arshiacomplus", config_index=1):
     if not best_ip_info or len(best_ip_info) < 2: rprint("[red]SingBox: Best IP missing.[/red]"); return None
     best_ip, best_port = best_ip_info
     outbounds = []
     # Warp-IR (if Germany mode)
     if isIran == '2':
         ir_outbound = { "type": "wireguard", "tag": f"Warp-IR-{config_index}", "local_address": ["172.16.0.2/32", keys1['Address']], "private_key": keys1['PrivateKey'], "server": "162.159.192.1", "server_port": 2408, "peer_public_key": keys1['PublicKey'], "reserved": keys1['Reserved'], "mtu": 1280 } # Fixed endpoint
         if use_noise: ir_outbound.update({"fake_packets":"1-3", "fake_packets_size":"10-30", "fake_packets_delay":"10-30", "fake_packets_mode":"m4"})
         outbounds.append(ir_outbound)
     # Warp-Main
     main_outbound = { "type": "wireguard", "tag": f"Warp-Main-{config_index}", "local_address": ["172.16.0.2/32", keys2['Address']], "private_key": keys2['PrivateKey'], "server": best_ip, "server_port": best_port, "peer_public_key": keys2['PublicKey'], "reserved": keys2['Reserved'], "mtu": 1330 }
     if isIran == '2': main_outbound["detour"] = f"Warp-IR-{config_index}" # Add detour if IR leg exists
     if use_noise: main_outbound["fake_packets_mode"] = "m4"
     outbounds.append(main_outbound)
     # Return just the list of outbounds for this pair
     return outbounds

def generate_wireguard_url(config, endpoint, add_noise=False, remark="Tel= @arshiacomplus wire"):
    required_keys = ['PrivateKey', 'PublicKey', 'Address', 'Reserved']
    if not config or not all(key in config and config[key] is not None for key in required_keys): rprint("[red]WG URL: Incomplete config dict.[/red]"); return None
    if not endpoint or ':' not in endpoint: rprint(f"[red]WG URL: Invalid endpoint {endpoint}.[/red]"); return None
    try:
        private_key_encoded = urlencode(config['PrivateKey'])
        public_key_encoded = urlencode(config['PublicKey']) # PEER's key
        address_parts = config['Address'].split('/')
        address_encoded = urlencode(address_parts[0]) + "/" + address_parts[1] if len(address_parts) == 2 else urlencode(config['Address'])
        reserved_encoded = urlencode(",".join(map(str, config['Reserved'])))
        base_url = f"wireguard://{endpoint}?privatekey={private_key_encoded}&publickey={public_key_encoded}&address=172.16.0.2/32,{address_encoded}"
        params = {}
        if add_noise: params = {"wnoise": "quic", "keepalive": "10", "wpayloadsize": "1-8", "wnoisedelay": "1-3", "wnoisecount": "15", "mtu": "1330"}
        else: params = {"mtu": "1280"}
        if reserved_encoded: params["reserved"] = reserved_encoded
        query_string = urllib.parse.urlencode(params)
        final_url = f"{base_url}&{query_string}#{urlencode(remark)}"
        return final_url
    except Exception as e: rprint(f"[red]Error creating WG URL: {e}[/red]"); return None


# --- Menu and Main Execution Logic ---

def start_menu():
    console.clear()
    ipv4_status, ipv6_status = check_ipv6()
    rprint(Panel(f' IPv4 Status: {ipv4_status}\n IPv6 Status: {ipv6_status}', title="Network Status", border_style="blue"))
    rprint(f'\n [bold cyan]Warp Scanner & Config Generator (v{V})[/bold cyan]')
    rprint(" [yellow]By: @arshiacomplus (Telegram & GitHub)[/yellow]\n")
    options = {
        "1": "Scan Cloudflare IPs (v4/v6)",
        "5": "Generate WireGuard URL (V2RayNG/MahsaNG)",
        "6": "Generate WG URL (No Scan)",
        "11": "Generate WG URL + Noise (NekoBox/MahsaNG)",
        "12": "Generate WG URL + Noise (No Scan)",
        "7": "Generate V2Ray WoW JSON",
        "13": "Generate V2Ray WoW JSON + Noise",
        "8": "Generate V2Ray WoW Sub Link -> QR", # Added QR indication
        "14": "Generate V2Ray WoW Sub Link + Noise -> QR", # Added QR indication
        "15": "Generate Sing-Box Outbounds JSON",
        "16": "Generate Sing-Box Outbounds (No Scan)",
        "17": "Generate Sing-Box Sub Link (Outbounds)", # Removed QR - not typical for singbox subs?
        "10": "Generate `wireguard.conf` File",
        "9": "Add/Delete Termux Shortcut",
        "4": "Clean Saved Scan Results File",
        "00": "Info / Contact", "0": "Exit"
    }
    term_width = gt_resolution()
    if term_width > 75:
        keys = list(options.keys()); half = (len(keys) + 1) // 2; rprint("[bold]Options:[/bold]")
        for i in range(half):
            key1, val1 = keys[i], options[keys[i]]; col1 = f" [bold yellow]{key1:>2}[/bold yellow]: {val1}"
            col2 = ""; key2=None
            if i + half < len(keys): key2, val2 = keys[i+half], options[keys[i+half]]; col2 = f" [bold yellow]{key2:>2}[/bold yellow]: {val2}"
            padding = max(0, 45 - len(col1)); rprint(f"{col1}{' ' * padding}{col2}")
        print()
    else:
         rprint("[bold]Options:[/bold]")
         for key, value in options.items(): rprint(f" [bold yellow]{key:>2}[/bold yellow]: {value}")
         print()
    what = Prompt.ask("Choose an option", choices=list(options.keys()), default="1") # Default to scan
    return what

def get_number_of_configs():
    while True:
        try: num = int(Prompt.ask('\nConfigs for subscription (e.g., 2-10)?', default="3")); return num if 1 <= num <= 20 else rprint("[red]Enter 1-20.[/red]")
        except ValueError: rprint("[red]Invalid number.[/red]")

def gojo_goodbye_animation():
    frames = ["\n\033[94m(＾-＾)ノ\033[0m Bye!", "\n\033[93m(＾-＾)ノ~~\033[0m See ya!", "\n\033[92m(＾-＾)ノ~~~~~\033[0m Done!"]
    for frame in frames: print(frame); time.sleep(0.6)

def get_manual_ip_endpoint(default_ip="162.159.195.166", default_port=878):
     endpoint_input = Prompt.ask(f'\nEnter IP:Port [default: {default_ip}:{default_port}]', default='n')
     if endpoint_input.lower() == 'n' or not endpoint_input.strip(): return f"{default_ip}:{default_port}"
     else:
         try: ip_part, port_part = endpoint_input.strip().split(':'); port_num = int(port_part); return endpoint_input.strip() if ('.' in ip_part or ':' in ip_part) and 1 <= port_num <= 65535 else rprint("[red]Invalid IP/Port. Using default.[/red]") or f"{default_ip}:{default_port}"
         except (ValueError, IndexError): rprint("[red]Invalid format. Using default.[/red]"); return f"{default_ip}:{default_port}"

# --- Main Execution Block ---
if __name__ == "__main__":
    try:
        while True:
            console.clear()
            what = start_menu()
            best_result = None # Reset best result before action

            # 1: Scan IPs
            if what == '1':
                main_scan_wrapper() # Scans and sets global best_result

            # 5, 6, 11, 12: Generate WireGuard URL -> QR
            elif what in ['5', '6', '11', '12']:
                endpoint = None; needs_scan = what in ['5', '11']; add_noise = what in ['11', '12']
                if needs_scan:
                    scan_result = main_scan_wrapper()
                    if scan_result: endpoint = f"{scan_result[0]}:{scan_result[1]}"
                    else: rprint("[red]Scan failed or found no IP. Cannot generate URL.[/red]"); continue
                else: endpoint = get_manual_ip_endpoint()
                if endpoint:
                     rprint(f"[cyan]Using endpoint: {endpoint}[/cyan]"); rprint("[cyan]Fetching keys...[/cyan]")
                     config_keys = free_cloudflare_account()
                     if config_keys:
                         wireguard_url = generate_wireguard_url(config_keys, endpoint, add_noise=add_noise)
                         if wireguard_url:
                             console.clear()
                             console.print(Panel(wireguard_url, title="[bold green]Generated WireGuard URL[/bold green]", border_style="green"))
                             generate_qr_code(wireguard_url) # Generate QR for the URL
                         else: rprint("[red]Failed to generate WireGuard URL.[/red]")
                     else: rprint("[red]Failed to fetch keys.[/red]")

            # 7, 13: Generate V2Ray WoW JSON (No QR for raw JSON)
            elif what in ['7', '13']:
                 add_noise = (what == '13')
                 rprint(f"[cyan]Generate V2Ray WoW Config {'(+ Noise)' if add_noise else ''}...[/cyan]")
                 scan_result = main_scan_wrapper()
                 if scan_result:
                     best_ip_info = scan_result; rprint(f"[cyan]Using best IP: {best_ip_info[0]}:{best_ip_info[1]}[/cyan]")
                     polrn_block = input_p('Block porn sites?', {"1": "Yes", "2": "No"}, '2')
                     isIran = input_p('Mode:', {"1": "Iran (Faster)", "2": "Germany (WoW)"}, '1')
                     rprint("[cyan]Fetching keys...[/cyan]")
                     keys1 = free_cloudflare_account(); time.sleep(0.5); keys2 = free_cloudflare_account()
                     if keys1 and keys2:
                         wow_config_json = generate_v2ray_wow_config(keys1, keys2, best_ip_info, add_noise=add_noise)
                         if wow_config_json:
                             console.clear()
                             console.print(Panel("[bold green]Generated V2Ray WoW JSON Config[/bold green]\n(Cannot generate QR for full JSON)", border_style="yellow"))
                             # Use Syntax object for highlighting
                             syntax = Syntax(wow_config_json, "json", theme="default", line_numbers=False)
                             console.print(syntax)
                             save_conf = Prompt.ask("Save to 'wow_config.json'?", choices=['y', 'n'], default='n')
                             if save_conf == 'y':
                                 try:
                                     with open("wow_config.json", "w") as f: f.write(wow_config_json)
                                     rprint("[green]Saved to wow_config.json[/green]")
                                 except IOError as e: rprint(f"[red]Error saving: {e}[/red]")
                         else: rprint("[red]Failed to generate WoW JSON.[/red]")
                     else: rprint("[red]Failed to get keys for WoW config.[/red]")
                 else: rprint("[red]Scan failed or found no IP. Cannot generate config.[/red]")

            # 8, 14: Generate V2Ray WoW Subscription Link -> QR
            elif what in ['8', '14']:
                 add_noise = (what == '14')
                 rprint(f"[cyan]Generate V2Ray WoW Subscription {'(+ Noise)' if add_noise else ''} -> QR...[/cyan]")
                 scan_result = main_scan_wrapper()
                 if scan_result:
                     best_ip_info = scan_result; rprint(f"[cyan]Using best IP: {best_ip_info[0]}:{best_ip_info[1]}[/cyan]")
                     polrn_block = input_p('Block porn?', {"1": "Yes", "2": "No"}, '2')
                     isIran = input_p('Mode:', {"1": "Iran", "2": "Germany"}, '1')
                     how_many = get_number_of_configs()
                     WoW_v2 = "" # Reset global string
                     rprint(f"[cyan]Generating {how_many} configs...[/cyan]")
                     if 'alive_bar' in globals() and callable(alive_bar):
                          with alive_bar(how_many, title="Generating Configs") as bar:
                              for n in range(how_many): generate_multiple_v2ray_wow(how_many, n, best_ip_info, add_noise); bar()
                     else:
                          for n in range(how_many): print(f"Generating config {n+1}/{how_many}..."); generate_multiple_v2ray_wow(how_many, n, best_ip_info, add_noise)

                     if WoW_v2:
                          final_sub_json_str = f"[ {WoW_v2} ]"
                          # ---> CHANGE: Upload and get link, then generate QR <---
                          download_link = upload_to_bashupload(final_sub_json_str) # Upload returns the link or None
                          if download_link:
                               # QR code is generated for the returned download_link
                               generate_qr_code(download_link)
                          else:
                               rprint("[red]Upload failed. Cannot generate QR code for subscription link.[/red]")
                          # ---> END CHANGE <---
                     else: rprint("[red]Failed to generate any valid configs.[/red]")
                 else: rprint("[red]Scan failed or found no IP. Cannot generate subscription.[/red]")

            # 15, 16: Generate Sing-Box Outbounds JSON
            elif what in ['15', '16']:
                 use_noise = False # Add noise option later
                 rprint(f"[cyan]Generate Sing-Box Warp Outbounds {'(+ Noise)' if use_noise else ''}...[/cyan]")
                 endpoint_ip_info = None
                 if what == '15': # Scan
                     scan_result = main_scan_wrapper()
                     if scan_result: endpoint_ip_info = scan_result; rprint(f"[cyan]Using IP: {endpoint_ip_info[0]}:{endpoint_ip_info[1]}[/cyan]")
                     else: rprint("[red]Scan failed.[/red]"); continue
                 else: # No Scan
                      endpoint_str = get_manual_ip_endpoint()
                      try: ip, port = endpoint_str.split(':'); endpoint_ip_info = [ip, int(port)]; rprint(f"[cyan]Using IP: {ip}:{port}[/cyan]")
                      except: rprint("[red]Invalid manual IP.[/red]"); continue
                 if endpoint_ip_info:
                     isIran = input_p('Mode:', {"1": "Iran (No Detour)", "2": "Germany (Detour)"}, '1')
                     rprint("[cyan]Fetching keys...[/cyan]")
                     keys1 = free_cloudflare_account(); time.sleep(0.5); keys2 = free_cloudflare_account()
                     if keys1 and keys2:
                         # generate_singbox_warp_config returns a list of 2 outbounds
                         singbox_outbounds_list = generate_singbox_warp_config(keys1, keys2, endpoint_ip_info, use_noise=use_noise, config_index=1)
                         if singbox_outbounds_list:
                              singbox_json_str = json.dumps({"outbounds": singbox_outbounds_list}, indent=2) # Wrap in {"outbounds": ...}
                              console.clear(); console.print(Panel("[bold green]Generated Sing-Box Outbounds JSON Fragment[/bold green]", border_style="green"))
                              syntax = Syntax(singbox_json_str, "json", theme="default", line_numbers=False); console.print(syntax)
                              save_conf = Prompt.ask("Save to 'sb_outbounds.json'?", choices=['y', 'n'], default='n')
                              if save_conf == 'y':
                                  try:
                                      with open("sb_outbounds.json", "w") as f: f.write(singbox_json_str)
                                      rprint("[green]Saved to sb_outbounds.json[/green]")
                                  except IOError as e: rprint(f"[red]Save error: {e}")
                         else: rprint("[red]Failed to generate Sing-Box JSON.[/red]")
                     else: rprint("[red]Failed to fetch keys.[/red]")

            # 17: Generate Sing-Box Subscription Link (List of Outbounds)
            elif what == '17':
                 use_noise = False
                 rprint(f"[cyan]Generate Sing-Box Subscription (Outbounds) {'(+ Noise)' if use_noise else ''}...[/cyan]")
                 scan_result = main_scan_wrapper()
                 if scan_result:
                     endpoint_ip_info = scan_result; rprint(f"[cyan]Using IP: {endpoint_ip_info[0]}:{endpoint_ip_info[1]}[/cyan]")
                     isIran = input_p('Mode:', {"1": "Iran", "2": "Germany"}, '1')
                     how_many = get_number_of_configs()
                     all_outbounds = [] # Collect all generated outbound dicts
                     rprint(f"[cyan]Generating {how_many} outbound pairs...[/cyan]")
                     gen_ok = True
                     if 'alive_bar' in globals() and callable(alive_bar):
                          with alive_bar(how_many, title="Generating Outbounds") as bar:
                              for i in range(how_many):
                                  keys1 = free_cloudflare_account(); time.sleep(0.5); keys2 = free_cloudflare_account()
                                  if keys1 and keys2:
                                      pair_outbounds = generate_singbox_warp_config(keys1, keys2, endpoint_ip_info, use_noise=use_noise, config_index=i+1)
                                      if pair_outbounds: all_outbounds.extend(pair_outbounds)
                                      else: gen_ok = False; rprint(f"[red]Pair {i+1} generation failed.[/red]")
                                  else: gen_ok = False; rprint(f"[red]Pair {i+1} key fetch failed.[/red]")
                                  bar()
                     else:
                          for i in range(how_many): # Basic progress
                               print(f"Generating pair {i+1}/{how_many}..."); keys1=free_cloudflare_account();time.sleep(0.5);keys2=free_cloudflare_account()
                               # ... (rest of logic inside loop) ...
                     if all_outbounds and gen_ok:
                          final_sub_structure = {"outbounds": all_outbounds}
                          final_sub_json_str = json.dumps(final_sub_structure, indent=2)
                          # ---> CHANGE: Upload Sing-Box sub and generate QR for link <---
                          download_link = upload_to_bashupload(final_sub_json_str)
                          if download_link:
                              # Generate QR for the Bashupload link containing the Sing-Box outbounds list
                              generate_qr_code(download_link)
                          else:
                              rprint("[red]Upload failed. Cannot generate QR code for Sing-Box subscription link.[/red]")
                          # ---> END CHANGE <---
                     elif not gen_ok: rprint("[red]Errors occurred. Subscription incomplete.[/red]")
                     else: rprint("[red]Failed to generate any valid outbounds.[/red]")
                 else: rprint("[red]Scan failed. Cannot generate subscription.[/red]")


            # 10: Generate wireguard.conf file
            elif what == '10':
                rprint("[cyan]Generate wireguard.conf file...[/cyan]")
                scan_result = main_scan_wrapper()
                if scan_result:
                    endpoint = f"{scan_result[0]}:{scan_result[1]}"; rprint(f"[cyan]Using IP: {endpoint}[/cyan]")
                    rprint("[cyan]Fetching keys...[/cyan]")
                    keys = free_cloudflare_account()
                    if keys:
                        conf_name = Prompt.ask('Filename (.conf) [acpwire]', default='acpwire').strip().replace(" ", "_")
                        conf_content = f"[Interface]\nPrivateKey = {keys['PrivateKey']}\nAddress = 172.16.0.2/32, {keys['Address']}\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = {keys['PublicKey']}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\n"
                        save_dir = "/storage/emulated/0/" if 'com.termux' in os.environ.get('PREFIX', '') else "."
                        save_path = os.path.join(save_dir, conf_name + ".conf")
                        try:
                            if save_dir == "/storage/emulated/0/": os.system('termux-setup-storage > /dev/null 2>&1')
                            os.makedirs(os.path.dirname(save_path), exist_ok=True)
                            with open(save_path, 'w') as f: f.write(conf_content)
                            rprint(f'\n[bold green]Saved to:[/bold green] {os.path.abspath(save_path)}')
                        except (IOError, OSError) as e: rprint(f"[red]Error saving file: {e}[/red]")
                    else: rprint("[red]Failed to fetch keys.[/red]")
                else: rprint("[red]Scan failed. Cannot generate .conf.[/red]")

            # 9: Add/Delete Termux Shortcut
            elif what == '9':
                 bashrc = '/data/data/com.termux/files/usr/etc/bash.bashrc'; bak = bashrc + '.bak'
                 if not os.path.exists(os.path.dirname(bashrc)): rprint("[red]Termux not detected.[/red]"); continue
                 if os.path.exists(bak):
                     if input_p('Delete existing shortcut?', {"1": "Yes", "2": "No"}, '2') == '1':
                         try: os.remove(bashrc); os.rename(bak, bashrc); console.print("[green]Shortcut removed. Restart Termux.[/green]")
                         except OSError as e: console.print(f"[red]Error: {e}[/red]")
                 else:
                     name = Prompt.ask("Shortcut command name (e.g., 'warp'): ").strip()
                     if name and not name.isdigit() and ' ' not in name:
                         sc_func = f'\n# WarpScanner Shortcut\n{name}() {{ bash <(curl -fsSL https://raw.githubusercontent.com/arshiacomplus/WarpScanner/main/install.sh); }}\n'
                         try: shutil.copy2(bashrc, bak); rprint(f"[dim]Backed up to {bak}[/dim]"); f=open(bashrc, 'a'); f.write(sc_func); f.close(); rprint(f"\n[green]Shortcut '{name}' added! Restart Termux and type '{name}'.[/green]")
                         except Exception as e: rprint(f"[red]Error: {e}[/red]"); os.path.exists(bak) and os.rename(bak, bashrc) # Restore on error
                     else: console.print("[red]Invalid name.[/red]")

            # 4: Clean Results File
            elif what == '4':
                 rprint("[cyan]Clean Saved Results File[/cyan]")
                 input_file = '/storage/emulated/0/result.csv'; output_file = '/storage/emulated/0/result_cleaned.csv'
                 if not os.path.exists(input_file): rprint(f"[red]Input not found: {input_file}[/red]"); continue
                 clean_format = input_p('Cleaned format:', {'1': 'BPB (Comma)', '2': 'Vahid (Newline)'}, '2')
                 include_port_clean = input_p('Include port?', {'1': 'Yes', '2': 'No'}, '1')
                 cleaned = []; lines = []
                 try:
                      with open(input_file, 'r') as f_in: lines = f_in.readlines()
                      for line in lines:
                          line = line.strip(); ip_part = line.split('|')[0].strip() if line else ""
                          if not ip_part: continue
                          if include_port_clean == '1': cleaned.append(ip_part)
                          else: cleaned.append(ip_part.split(':')[0].strip()) # IP only
                      cleaned = list(dict.fromkeys(cleaned)) # Remove duplicates
                      with open(output_file, 'w') as f_out:
                          f_out.write(("," if clean_format == '1' else "\n").join(cleaned)); f_out.write("\n")
                      rprint(f"[bold green]Cleaned results saved to:[/bold green] {output_file}")
                 except (IOError, OSError) as e: rprint(f"[red]File error: {e}[/red]")
                 except Exception as e: rprint(f"[red]Cleaning error: {e}[/red]")

            # 00: Info
            elif what == '00': info()

            # 0: Exit
            elif what == '0': break

            # --- Wait for user ---
            if what != '0': Prompt.ask("\nPress Enter to return to menu...") # Use rich prompt

        # --- End of Script ---
        gojo_goodbye_animation()
        console.print("[bold magenta]Exiting script... Goodbye![/bold magenta]")

    except KeyboardInterrupt: print("\n"); gojo_goodbye_animation(); console.print("[bold yellow]Script interrupted. Exiting.[/bold yellow]")
    except Exception as e:
         console.print("\n[bold red]An unexpected error occurred:[/bold red]")
         console.print_exception(show_locals=False) # Print full traceback using rich
         console.print("[bold red]Exiting due to error.[/bold red]")

    sys.exit(0) # Normal exit code

