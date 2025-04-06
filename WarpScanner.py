# -*- coding: utf-8 -*-
V=71
import urllib.request
import urllib.parse
from urllib.parse import quote
import os
try:
    import requests
except Exception:
    print("Requests module not installed. Installing now...")
    os.system('pip install requests')
try:
    import requests
except Exception:
    os.system('wget https://github.com/psf/requests/releases/download/v2.32.2/requests-2.32.2.tar.gz')
    os.system('tar -xzvf requests-2.32.2.tar.gz')
    os.chdir('requests-2.32.2')
    os.system('python setup.py install')
try:
    import requests
except Exception:
    os.system('curl -L -o requests-2.32.2.tar.gz https://github.com/psf/requests/releases/download/v2.32.2/requests-2.32.2.tar.gz')
    os.system('tar -xzvf requests-2.32.2.tar.gz')
    os.chdir('requests-2.32.2')
    os.system('python setup.py install')
    import requests
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
try:
    import rich
except Exception:
    print("Rich module not installed. Installing now...")
    os.system('pip install rich')
from rich.console import Console
from rich.prompt import Prompt
from rich import print as rprint
from rich.table import Table
try:
    import retrying
except Exception:
    print("retrying module not installed. Installing now...")
    os.system('pip install retrying')
try:
    import retrying
except Exception:
    os.system("wget https://github.com/rholder/retrying/archive/refs/tags/v1.3.3.tar.gz")
    os.system("tar -zxvf v1.3.3.tar.gz")
    os.chdir("retrying-1.3.3")
    os.system("python setup.py install")
from retrying import retry
from requests.exceptions import ConnectionError

import random
import subprocess
import json
import sys
try:
    from icmplib import ping as pinging
except Exception:
    os.system('pip install icmplib')
    from icmplib import ping as pinging

import base64
try:
    import datetime
except Exception:
    os.system('pip install datetime')
    import datetime
try:
    from alive_progress import alive_bar
except Exception:
    os.system("pip install alive_progress")
    from alive_progress import alive_bar

# --- Cryptography installation handled later in fetch_config_from_api ---

api=''
ports = [1074, 894, 908, 878]
console = Console()
wire_config_temp=''
wire_c=1
wire_p=0
send_msg_wait=0
results=[]
resultss=[]
save_result=[]
save_best=[]
best_result=[]
WoW_v2=''
isIran=''
max_workers_number=0
do_you_save='2'
which=''
ping_range='n'

# --- Existing Helper Functions (unchanged unless specified) ---

def gt_resolution():
    return os.get_terminal_size().columns

def info():
    console.clear()

    table = Table(show_header=True,title="Info", header_style="bold blue")
    table.add_column("Creator", width=15)

    table.add_column("contact", justify="right")
    table.add_row("arshiacomplus","1 - Telegram")
    table.add_row("arshiacomplus","2 - github")
    console.print(table)

    print('\nEnter a Number\n')
    options2={"1" : "open Telegram Channel", "2" : "open github ", "0":"Exit"}
    for key, value in options2.items():
        rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    whats2 = Prompt.ask("Choose an option", choices=list(options2.keys()), default="1")

    if whats2=='0':
        os.execv(sys.executable, ['python'] + sys.argv)
    elif whats2=='1':
        os.system("termux-open-url 'https://t.me/arshia_mod_fun'")
    elif whats2=='2'   :
        os.system("termux-open-url 'https://github.com/arshiacomplus/'")

def check_ipv6():

    try:
        ipv6 = requests.get('http://v6.ipv6-test.com/api/myip.php', timeout=15)
        if ipv6.status_code == 200:
            ipv6 ="[green]Available[/green]"
    except Exception:
        ipv6 = "Unavailable"
    try:
        ipv4 = requests.get('http://v4.ipv6-test.com/api/myip.php',timeout=15)
        if ipv4.status_code == 200:
            ipv4= "[green]Available[/green]"
    except Exception:
        ipv4 = "Unavailable"
    return  [ipv4,ipv6]

def input_p(pt ,options):
    #os.system('clear') # Keep clear out of reusable function if possible
    options.update({"0" : "Exit"})
    print(pt)
    for key, value in options.items():
        rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    whats = Prompt.ask("Choose an option", choices=list(options.keys()), default="1")
    if whats=='0':
        os.execv(sys.executable, ['python'] + sys.argv)
    return whats

def urlencode(string):

    if string is None:
        return None
    return urllib.parse.quote(string, safe='a-zA-Z0-9.~_-')

def byte_to_base64(myb):
    """Converts bytes to a Base64 encoded string."""
    if not isinstance(myb, bytes):
         raise TypeError("Input must be bytes")
    return base64.b64encode(myb).decode('utf-8')

# --- NEW Cloudflare WARP Registration Logic ---

def generate_private_key_new():
    """Generates a new X25519 private key object."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.generate()

def get_public_key_hex(private_key_obj):
    """Gets the public key as a hex string from a private key object."""
    public_key = private_key_obj.public_key()
    return public_key.public_bytes_raw().hex()

@retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, (requests.exceptions.RequestException, json.JSONDecodeError)))
def register_key_on_CF_new(public_key_hex):
    """Registers the public key (hex) with the Cloudflare API."""
    # url = "https://api.cloudflareclient.com/v0a745/reg" # Original from snippet
    # Let's try a potentially newer one seen in other contexts, fallback if needed
    url = "https://api.cloudflareclient.com/v0a1091/reg" # Try this one

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
        'CF-Client-Version': 'a-6.37-4056' # Example version, might need update
    }
    # Generate a random install ID
    install_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=22))
    # Generate a fake FCM token (length can vary, 152 is common)
    fcm_token = install_id + ':' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_', k=130))

    data = {
        "key": public_key_hex,
        "install_id": install_id,
        "fcm_token": fcm_token,
        "warp_enabled": False, # Start with false, can be updated later if needed
        "tos": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "type": "Android",
        "model": "PC", # Keep model as PC from old script
        "locale": "en_US"
    }
    try:
        r = requests.post(url, headers=headers, json=data, timeout=20)
        r.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        response_json = r.json()
        # print(f"[DEBUG] API Response: {json.dumps(response_json, indent=2)}") # Debug print
        return response_json
    except requests.exceptions.RequestException as e:
        print(f"[!] Registration network error: {e}")
        # Fallback URL if the first one fails
        url = "https://api.cloudflareclient.com/v0a745/reg" # Fallback to original
        print(f"[!] Retrying with fallback URL: {url}")
        try:
            r = requests.post(url, headers=headers, json=data, timeout=20)
            r.raise_for_status()
            response_json = r.json()
            # print(f"[DEBUG] API Response (Fallback): {json.dumps(response_json, indent=2)}") # Debug print
            return response_json
        except requests.exceptions.RequestException as e2:
             print(f"[!] Fallback registration network error: {e2}")
             raise # Re-raise the exception to trigger retry
    except json.JSONDecodeError as e:
        print(f"[!] Failed to decode JSON response: {e}")
        print(f"[!] Response Text: {r.text}")
        raise # Re-raise the exception to trigger retry
    except Exception as e:
        print(f"[!] An unexpected error occurred during registration: {e}")
        raise

def bind_keys_new():
    """Generates keys and registers using the new API method."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey # Ensure import

    try:
        print("[*] Generating new key pair...")
        private_key_obj = generate_private_key_new()

        # Get Private Key in Base64 for output
        private_key_bytes = private_key_obj.private_bytes_raw()
        private_key_base64 = byte_to_base64(private_key_bytes)
        # print("[DEBUG] Private Key (Base64):", private_key_base64) # Debug print

        # Get Public Key in Hex for API call
        public_key_hex = get_public_key_hex(private_key_obj)
        # print("[+] Public Key (Hex):", public_key_hex) # Debug print

        print("[*] Registering key with Cloudflare API...")
        result = register_key_on_CF_new(public_key_hex)

        if result and isinstance(result, dict) and "config" in result:
            print("[+] Registered successfully!")
            # print(json.dumps(result, indent=4)) # Optional: print full result

            # --- Extract required information ---
            config = result.get('config', {})
            interface = config.get('interface', {})
            addresses = interface.get('addresses', {})
            ipv6_address = addresses.get('v6')

            peers = config.get('peers', [])
            peer_public_key_base64 = None
            reserved_list = None

            if peers and isinstance(peers, list) and len(peers) > 0:
                 # Assume the first peer is the relevant one
                 peer_info = peers[0]
                 peer_public_key_base64 = peer_info.get('public_key') # Already Base64

                 # Extract reserved bytes
                 reserved_data = peer_info.get('reserved') # Might be list or None
                 if isinstance(reserved_data, list) and all(isinstance(x, int) for x in reserved_data):
                      if len(reserved_data) == 3: # Check length
                           reserved_list = reserved_data
                      else:
                           print(f"[!] Warning: 'reserved' field has unexpected length: {len(reserved_data)}. Using default.")
                           # Provide a default or handle error - Using old default as fallback
                           # reserved_list = [222, 6, 184] # Example fallback from old code if needed
                 else:
                     print("[!] Warning: 'reserved' field missing or invalid format in API response. Cannot proceed.")
                     # Fallback: Try decoding account ID if reserved isn't directly available (less common now)
                     account_id = result.get('id')
                     if account_id:
                         print("[!] Trying fallback: Decoding account ID for reserved bytes.")
                         try:
                             cid_byte = base64.b64decode(account_id)
                             if len(cid_byte) == 3: # Check length after decoding
                                 reserved_list = [int(j) for j in cid_byte]
                                 print("[+] Fallback successful: Reserved bytes from account ID.")
                             else:
                                 print(f"[!] Fallback failed: Decoded account ID length is not 3: {len(cid_byte)}")
                         except Exception as decode_err:
                             print(f"[!] Fallback failed: Error decoding account ID: {decode_err}")


            # --- Validate extracted data ---
            if not ipv6_address:
                print("[!] Error: Could not extract IPv6 address from API response.")
                return None
            if not peer_public_key_base64:
                 # Use the known public key if API doesn't provide it reliably
                peer_public_key_base64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                print(f"[!] Warning: Could not extract peer public key. Using default: {peer_public_key_base64}")
            if not reserved_list:
                print("[!] Error: Could not determine reserved bytes. Registration failed.")
                return None # Cannot proceed without reserved bytes

            print(f"[DEBUG] Extracted Address: {ipv6_address}")
            print(f"[DEBUG] Extracted Reserved: {reserved_list}")
            print(f"[DEBUG] Peer Public Key: {peer_public_key_base64}")


            # Return the data in the format expected by fetch_config_from_api
            # (Address, PrivateKey_Base64, Reserved_List, PeerPublicKey_Base64)
            return (ipv6_address, private_key_base64, reserved_list, peer_public_key_base64)

        else:
            print("[!] Registration failed or response format unexpected.")
            print(f"[DEBUG] API Result: {result}")
            return None

    except ImportError:
         print("[!] Error: cryptography library is not installed correctly.")
         return None
    except Exception as e:
        import traceback
        print(f"[!] Error during key generation/registration: {e}")
        print(traceback.format_exc()) # Print full traceback for debugging
        return None


# --- Modified fetch_config_from_api ---

def fetch_config_from_api():
    """Fetches WARP config using either the old or new API method."""
    global api
    if api=='':
        # Keep API selection logic
        which_api=input_p('Which Api \n', {'1':'First api (s9.serv00.com)', '2' :'Second api (Cloudflare - requires crypto lib)'})
        api=which_api
    else:
        which_api=api

    if which_api == '2':
        # --- New API method ---
        print("[*] Using Cloudflare API (Method 2)")
        # Ensure cryptography is installed
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            print("[+] Cryptography library found.")
        except ImportError:
            print("[!] Cryptography library not found. Attempting installation...")
            try:
                print("   Attempting pip install...")
                os.system('pip install cryptography') # Simpler install first
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey # Try importing again
                print("[+] Cryptography installed via pip.")
            except Exception as e1:
                print(f"[!] Pip install failed: {e1}. Trying advanced install...")
                try:
                    # Keep the more robust installation commands if pip fails
                    print("   Running: pkg install python3 rust binutils-is-llvm -y")
                    os.system('pkg install python3 rust binutils-is-llvm -y')
                    print("   Running: export CXXFLAGS=\"-Wno-register\"")
                    os.system('export CXXFLAGS="-Wno-register"')
                    print("   Running: export CFLAGS=\"-Wno-register\"")
                    os.system('export CFLAGS="-Wno-register"')
                    print("   Running: python3 -m pip install cryptography")
                    os.system('python3 -m pip install cryptography')
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey # Final import attempt
                    print("[+] Cryptography installed via advanced method.")
                except Exception as e2:
                    # Fallback to manual download if everything else fails
                    print(f"[!] Advanced install failed: {e2}. Trying manual download...")
                    try:
                        os.system("wget https://github.com/pyca/cryptography/archive/refs/tags/43.0.0.tar.gz")
                        os.system("tar -zxvf 43.0.0.tar.gz")
                        os.chdir("cryptography-43.0.0")
                        os.system("pip install .")
                        os.chdir("..") # Go back to original directory
                        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey # Last chance
                        print("[+] Cryptography installed via manual download.")
                    except Exception as e3:
                        print(f"[!] Manual download install failed: {e3}")
                        print("[!] Critical Error: Could not install cryptography library. Please install it manually and restart.")
                        exit(1) # Exit if crypto cannot be installed

        # Call the new key binding function
        keys_tuple = bind_keys_new()

        if keys_tuple:
            # Convert the tuple to the dictionary format expected by the rest of the script
            return {
                'PrivateKey': keys_tuple[1],
                'PublicKey':  keys_tuple[3], # Peer public key
                'Reserved':   keys_tuple[2],
                'Address':    keys_tuple[0]
            }
        else:
            print("[!] Failed to bind keys using the new API method.")
            # Optionally, you could fallback to the old method here or just exit
            print("[!] Exiting due to key generation failure.")
            exit(1)


    elif which_api == '1':
        # --- Original API method (s9.serv00.com) ---
        print("[*] Using s9.serv00.com API (Method 1)")
        @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
        def file_o():
            try:
                response = urllib.request.urlopen("http://s9.serv00.com:1074/arshiacomplus/api/wirekey", timeout=30).read().decode('utf-8')
                return response
            except Exception as e:
                 print(f"[!] urllib request failed: {e}. Trying requests...")
                 response = requests.get("http://s9.serv00.com:1074/arshiacomplus/api/wirekey", timeout=30)
                 response.raise_for_status() # Check for HTTP errors
                 return response.text

        try:
            b = file_o()
            b = b.strip().split("\n") # Strip whitespace and split
            if len(b) < 4:
                raise ValueError("API response format unexpected (less than 4 lines)")

            Address_key = b[0].split(":", 1)[1].strip()
            private_key = b[1].split(":", 1)[1].strip()
            reserved_str = b[2].split(":", 1)[1].strip().split(" ")

            # Original code removed 4th item, let's replicate IF it exists and is valid
            # reserved = [int(item) for item in reserved_str if item.isdigit()] # More robust parsing
            # It seems the original API might have had an extra item sometimes?
            # Let's just take the first 3 valid integers if possible.
            reserved = []
            for item in reserved_str:
                 if item.isdigit():
                      reserved.append(int(item))
                 if len(reserved) == 3:
                      break # Stop after getting 3 integers

            if len(reserved) != 3:
                 raise ValueError(f"Could not parse 3 reserved integers from: {reserved_str}")

            pub_key = b[3].split(":", 1)[1].strip()

            return {
                'PrivateKey': private_key,
                'PublicKey': pub_key, # Use the public key from this API
                'Reserved': reserved,
                'Address': Address_key
            }
        except ConnectionError:
            console.print("[bold red]Failed to connect to s9.serv00.com API after retries.[/bold red]")
            exit(1)
        except Exception as e:
             console.print(f"[bold red]Error processing response from s9.serv00.com API: {e}[/bold red]")
             exit(1)
    else:
        print(f"[!] Invalid API choice: {which_api}")
        exit(1)


# --- Wrapper function to keep compatibility with old calls ---
def free_cloudflare_account():
    """Calls fetch_config_from_api to get keys. Main entry point for key generation."""
    # This function now just calls the main fetching logic
    try:
        config_dict = fetch_config_from_api()
        if not config_dict:
            raise ValueError("Failed to fetch configuration.")
         # The rest of the script expects a list: [Address, PrivateKey, Reserved, PublicKey]
         # Convert the dictionary back to this list format IF needed by the caller.
         # Let's check where `free_cloudflare_account` is called.
         # - main2_1/main2_2 uses it and expects a list.
         # - main3 uses it and expects a list.
         # - what=='10' uses it and expects a list.
         # So, we MUST return a list here.
        return [
            config_dict['Address'],
            config_dict['PrivateKey'],
            config_dict['Reserved'],
            config_dict['PublicKey']
        ]
    except Exception as e:
        print(f"[!] Error in free_cloudflare_account: {e}")
        print("[!] Exiting.")
        exit(1)


# --- Rest of the existing script (IP scanning, config generation, menus, etc.) ---
# --- This part remains largely unchanged, as it uses the data ---
# --- returned by free_cloudflare_account() / fetch_config_from_api() ---

def upload_to_bashupload(config_data):
    @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
    def file_o():
        files = {'file': ('output.json', config_data)}
        try:
            response = requests.post('https://bashupload.com/', files=files, timeout=30)
        except Exception:
            response = requests.post('https://bashupload.com/', files=files, timeout=50)
        return response
    try:

        response = file_o()

        if response.ok:
            download_link = response.text.strip()
            # Improved parsing for the download link
            match = re.search(r'(https://bashupload\.com/\w+)', download_link)
            if match:
                 base_link = match.group(1)
                 download_link_with_query = base_link + "?download=1"
                 console.print(f'[green]Your link: {download_link_with_query}[/green]')
            else:
                 console.print("[yellow]Could not parse download link automatically, showing full response:[/yellow]")
                 print(download_link)
        else:
            console.print(f"[red]Something happened with creating the link. Status: {response.status_code}[/red]", style="bold red")
            print(f"Response: {response.text}")
    except Exception as e:
        console.print(f"[red]An error occurred during upload: {e}[/red]", style="bold red")


def create_ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split('.')))
    end = list(map(int, end_ip.split('.')))
    temp = start[:]
    ip_range = []

    while temp != end:
        ip_range.append('.'.join(map(str, temp)))
        temp[3] += 1
        for i2 in (3, 2, 1):
            if temp[i2] == 256:
                temp[i2] = 0
                temp[i2-1] += 1
    ip_range.append(end_ip)
    return ip_range

def scan_ip_port(ip, results :list):
    # Use global ports list
    port=ports[random.randint(0,len(ports)-1)] # Select from global list

    icmp=None
    try:
        icmp = pinging(ip, count=4, interval=0.2, timeout=1, privileged=False) # Faster ping

        if icmp and icmp.is_alive:
            # Handle None values safely
            avg_rtt = icmp.avg_rtt if icmp.avg_rtt is not None else 1000.0 # Assign high ping if None
            packet_loss = icmp.packet_loss if icmp.packet_loss is not None else 1.0 # Assign high loss if None
            jitter = icmp.jitter if icmp.jitter is not None else 1000.0 # Assign high jitter if None
            results.append((ip, port, float(avg_rtt), packet_loss, float(jitter)))

    except Exception as e:
        # print(f"Error pinging {ip}: {e}") # Optional debug
        pass # Ignore errors during ping and continue

def main_v6():
    global which
    global ping_range
    global save_best
    global resultss
    global do_you_save # Make sure global is declared if modified
    global need_port # Make sure global is declared if used before assignment

    resultss=[]
    save_best = [] # Initialize save_best for IPv6

    def generate_ipv6():
        # Simplified generator focusing on likely Cloudflare ranges
        # return f"2606:4700:d{random.randint(0, 1)}::{random.randint(0, 65535):x}:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}"
        # Try focusing on known edge ranges
         prefix = random.choice(["2606:4700:10::", "2606:4700:20::", "2606:4700:30::", "2606:4700:d0::", "2606:4700:d1::"])
         suffix = f"{random.randint(0, 65535):x}:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}"
         return prefix + suffix


    def ping_ip_v6(ip, port): # Renamed to avoid conflict
        global resultss # Access global results list

        icmp_v6 = None
        try:
            # icmplib might need family='ipv6', but often detects automatically. Explicit is safer.
            icmp_v6 = pinging(ip, count=4, interval=0.2, timeout=1, privileged=False, family=6) # Specify family=6

            if icmp_v6 and icmp_v6.is_alive:
                 avg_rtt = icmp_v6.avg_rtt if icmp_v6.avg_rtt is not None else 1000.0
                 packet_loss = icmp_v6.packet_loss if icmp_v6.packet_loss is not None else 1.0
                 jitter = icmp_v6.jitter if icmp_v6.jitter is not None else 1000.0
                 resultss.append((ip, port, float(avg_rtt), packet_loss, float(jitter)))

        except Exception as e:
             # print(f"Error pinging IPv6 {ip}: {e}") # Optional debug
             pass # Ignore ping errors


    # Use global ports list
    ports_to_check = ports # Use the global ports list [1074, 894, 908, 878]

    random_ip=generate_ipv6() # Generate one for potential fallback
    best_ping=1000.0 # Float for comparison
    best_ip=""

    table = Table(show_header=True, title="IPv6 Scan Results", header_style="bold blue")
    table.add_column("IP", style="dim", width=35) # Wider for IPv6
    table.add_column("Port", justify="right")
    table.add_column("Ping (ms)", justify="right")
    table.add_column("Packet Loss (%)", justify="right")
    table.add_column("Jitter (ms)", justify="right")
    table.add_column("Score", justify="right")


    # Determine number of IPs to scan - make it configurable or fixed
    num_ips_to_scan = 500 # Example: scan 500 random IPs
    max_workers_scan = 100 # Limit workers for scanning phase

    print(f"[*] Scanning {num_ips_to_scan} random IPv6 addresses...")
    executor= ThreadPoolExecutor(max_workers=max_workers_scan)
    futures = []
    print("\033[1;35m") # Magenta color start
    try:
        for _ in range(num_ips_to_scan):
            ip_to_scan = generate_ipv6()
            port_to_scan = random.choice(ports_to_check)
            futures.append(executor.submit(ping_ip_v6, ip_to_scan, port_to_scan))

        none=gt_resolution()
        bar_size=min( none-40, 20)
        bar_size = max(3, bar_size) # Ensure minimum size 3

        with alive_bar(total=len(futures), length=bar_size, title="Scanning IPv6") as bar:
            for future in as_completed(futures):
                 try:
                      future.result() # We just need to know it finished, result handled in callback
                 except Exception as exc:
                      # print(f'Generated an exception: {exc}') # Optional debug
                      pass
                 bar() # Increment progress bar

    except Exception as E:
            rprint('[bold red]An Error Occurred During IPv6 Scan: [/bold red]', E)
    finally:
            executor.shutdown(wait=True)
    print("\033[0m") # Reset color

    print(f"[*] Found {len(resultss)} responsive IPv6 addresses. Calculating scores...")

    extended_results=[]
    for result_item in resultss: # Use different variable name
        ip, port, ping ,loss_rate,jitter= result_item
        # Use safe defaults if values are somehow invalid
        ping = float(ping) if isinstance(ping, (int, float)) and ping >= 0 else 1000.0
        loss_rate = float(loss_rate) if isinstance(loss_rate, (int, float)) and 0.0 <= loss_rate <= 1.0 else 1.0
        jitter = float(jitter) if isinstance(jitter, (int, float)) and jitter >= 0 else 1000.0

        # Penalize high values before scoring
        ping = 1000.0 if ping == 0.0 else ping # Treat 0 ping as high ping
        jitter = 1000.0 if jitter == 0.0 else jitter # Treat 0 jitter as high jitter

        loss_percentage = loss_rate * 100

        # Scoring weights (adjust as needed)
        # Lower score is better
        combined_score = (0.6 * ping) + (0.3 * loss_percentage * 10) + (0.1 * jitter) # Heavily penalize loss
        # Add penalty for complete loss
        if loss_rate == 1.0:
            combined_score += 5000

        extended_results.append((ip, port, ping, loss_percentage, jitter, combined_score))

    # Sort the results based on combined score (lower is better)
    sorted_results = sorted(extended_results, key=lambda x: x[5])


    # Process sorted results for display and saving
    for ip, port, ping, loss_p, jitter_val, score in sorted_results:
        # Saving logic (only if do_you_save is '1')
        if do_you_save == '1':
            # Common condition: valid ping and low loss (e.g., < 5%)
            if ping < 999 and loss_p < 5.0:
                # Check against ping range if specified
                ping_range_int = 1000 # Default high value if ping_range isn't set or invalid
                try:
                    ping_range_int = int(ping_range)
                except (ValueError, TypeError):
                    pass # Use default if conversion fails

                if ping <= ping_range_int:
                    # Format based on 'which' and 'need_port'
                    if which == '1': # bpb (comma)
                        if need_port == '1':
                            save_best.append(f"[{ip}]:{port},")
                        else:
                            save_best.append(f"[{ip}],")
                    elif which == '2': # vahid (newline)
                        if need_port == '1':
                             save_best.append(f"[{ip}]:{port}\n")
                        else:
                             save_best.append(f"[{ip}]\n")
                    elif which == '3': # with score
                         if need_port == '1':
                              save_best.append(f"[{ip}]:{port} | ping: {ping:.2f} loss: {loss_p:.2f}% jitter: {jitter_val:.2f}\n")
                         else: # need_port == '2'
                              save_best.append(f"[{ip}] | ping: {ping:.2f} loss: {loss_p:.2f}% jitter: {jitter_val:.2f}\n")
                    # Note: 'which == 4' (clean) is handled separately after main()

        # Add top results to the display table (e.g., top 10 or 20)
        if len(table.rows) < 20: # Show top 20 results
             table.add_row(
                 ip,
                 str(port),
                 f"{ping:.2f}",
                 f"{loss_p:.2f}%",
                 f"{jitter_val:.2f}",
                 f"{score:.2f}"
             )

        # Track the best IP based on score (lowest score wins)
        current_best_score = sorted_results[0][5] if sorted_results else float('inf')
        if score <= current_best_score and ping < 999 and loss_p < 5: # Ensure it's a usable IP
             if score < best_ping: # Update best if current score is lower
                  best_ping = score # Store the score as 'best_ping' metric for v6
                  best_ip = ip
                  best_port = port # Store the corresponding port


    os.system("clear")
    console.print(table) # Display the table

    # Save results to file if requested
    if do_you_save == '1' and save_best:
         # Remove trailing comma/newline from the last entry if necessary
        if which == '1' and save_best[-1].endswith(','):
             save_best[-1] = save_best[-1][:-1]
        elif which == '2' and save_best[-1].endswith('\n'):
             # Newlines are fine for 'vahid' format, keep it
             pass

        try:
            filepath = '/storage/emulated/0/result_v6.csv' # Use a different name for v6 results
            with open(filepath, "w") as f:
                f.writelines(save_best) # Use writelines for list of strings
            print(f'IPv6 results saved in {filepath} !')
        except Exception as e:
            print(f"[!] Error saving IPv6 results: {e}")

    # Determine final best IP to return
    best_ip_mix = [None, None]
    if best_ip:
        # Use the best found IP
        console.print(f"\n[bold green]Best IPv6 : [{best_ip}]:{best_port} with score: {best_ping:.2f}[/bold green]")
        best_ip_mix[0] = f"[{best_ip}]" # Keep brackets for consistency
        best_ip_mix[1] = best_port
    else:
        # Fallback if no good IP was found
        fallback_port = random.choice(ports_to_check)
        console.print(f"\n[bold yellow]No suitable IPv6 found. Using random fallback: [{random_ip}]:{fallback_port}[/bold yellow]")
        best_ip_mix[0] = f"[{random_ip}]"
        best_ip_mix[1] = fallback_port

    return best_ip_mix


def main():
    global which
    global max_workers_number
    global ping_range
    global do_you_save # Declare global
    global need_port  # Declare global
    global save_result # Declare global

    ping_range_input = 'n' # Use different var name
    results = [] # Ensure results is reset for IPv4 scan
    save_result = [] # Ensure save_result is reset

    if do_you_save == '1':
        ping_range_input = Prompt.ask('\nEnter max ping (ms) for saving IPs [Default=300, n=skip]: ', default='300')
        if ping_range_input.lower() == 'n':
            ping_range = '1000' # Effectively skip ping limit if 'n'
        else:
            try:
                # Validate input is a number
                ping_range_int = int(ping_range_input)
                ping_range = str(ping_range_int) # Store as string
            except ValueError:
                print("[!] Invalid ping range, using default 300ms.")
                ping_range = '300'


    # Ask for IP version *within* main now
    # Keep 'what' check for context, assume 'what' is passed or global if needed
    # For now, assume 'what' might influence behavior later, but version choice is here
    global what # Need access to 'what' if it influences IP version choice logic

    if what != '0': # Example condition using 'what'
        which_v = input_p('Choose an IP version for scanning\n ', {"1": 'IPv4', "2": 'IPv6'})
        if which_v == "2":
            console.clear()
            best_result_v6 = main_v6() # Call the IPv6 scanner
            return best_result_v6 # Return the result from IPv6 scan

    # --- Proceed with IPv4 Scan ---
    Cpu_speed = input_p('Select scan power', {"1" : "Faster (More CPU)", "2" : "Slower (Less CPU)"})
    if Cpu_speed == "1":
        max_workers_number = 1000 # Higher thread count
        ping_interval = 0.15      # Shorter interval
        ping_timeout = 0.8        # Shorter timeout
    else: # Cpu_speed == "2"
        max_workers_number = 500  # Lower thread count
        ping_interval = 0.2
        ping_timeout = 1.0

    console.clear()
    console.print("Please wait, scanning IPv4 addresses...", style="blue")

    # Cloudflare IPv4 ranges (add more if needed)
    start_ips = ["188.114.96.0", "162.159.192.0", "162.159.195.0", "188.114.97.0", "188.114.98.0"]
    end_ips   = ["188.114.96.224", "162.159.193.224", "162.159.195.224", "188.114.97.224", "188.114.98.224"]
    # Use global ports list
    # ports = [1074, 894, 908, 878] # Defined globally

    all_ips_to_scan = []
    print("[*] Generating IP ranges...")
    for start_ip, end_ip in zip(start_ips, end_ips):
        all_ips_to_scan.extend(create_ip_range(start_ip, end_ip))

    print(f"[*] Total IPs to scan: {len(all_ips_to_scan)}")
    print(f"[*] Max workers: {max_workers_number}, Interval: {ping_interval}s, Timeout: {ping_timeout}s")


    # --- Modified scan_ip_port for IPv4 with adjusted parameters ---
    def scan_ip_port_v4(ip, results_list):
        port_v4 = random.choice(ports) # Use global ports list
        icmp_v4 = None
        try:
            icmp_v4 = pinging(ip, count=4, interval=ping_interval, timeout=ping_timeout, privileged=False, family=4) # Specify family=4

            if icmp_v4 and icmp_v4.is_alive:
                avg_rtt = icmp_v4.avg_rtt if icmp_v4.avg_rtt is not None else 1000.0
                packet_loss = icmp_v4.packet_loss if icmp_v4.packet_loss is not None else 1.0
                jitter = icmp_v4.jitter if icmp_v4.jitter is not None else 1000.0
                results_list.append((ip, port_v4, float(avg_rtt), packet_loss, float(jitter)))
        except Exception:
            pass # Ignore errors silently


    # --- Execute IPv4 Scan ---
    executor_v4 = ThreadPoolExecutor(max_workers=max_workers_number)
    futures_v4 = []
    print("\033[1;35m") # Magenta start
    try:
        for ip_addr in all_ips_to_scan:
            futures_v4.append(executor_v4.submit(scan_ip_port_v4, ip_addr, results)) # Use global results list

        none_res = gt_resolution()
        bar_size_v4 = min(none_res - 40, 20)
        bar_size_v4 = max(3, bar_size_v4)

        with alive_bar(total=len(futures_v4), length=bar_size_v4, title="Scanning IPv4") as bar_v4:
            for future in as_completed(futures_v4):
                 try:
                      future.result() # Wait for completion
                 except Exception:
                      pass # Ignore exceptions from futures
                 bar_v4() # Increment bar

    except Exception as E:
        print(f"Error during IPv4 scan execution: {E}")
    finally:
        executor_v4.shutdown(wait=True)
    print("\033[0m") # Reset color

    print(f"[*] Found {len(results)} responsive IPv4 addresses. Calculating scores...")

    # --- Process IPv4 Results ---
    extended_results_v4 = []
    for result_item in results: # Use different variable name
        ip, port, ping, loss_rate, jitter = result_item
        ping = float(ping) if isinstance(ping, (int, float)) and ping >= 0 else 1000.0
        loss_rate = float(loss_rate) if isinstance(loss_rate, (int, float)) and 0.0 <= loss_rate <= 1.0 else 1.0
        jitter = float(jitter) if isinstance(jitter, (int, float)) and jitter >= 0 else 1000.0

        ping = 1000.0 if ping == 0.0 else ping
        jitter = 1000.0 if jitter == 0.0 else jitter

        loss_percentage = loss_rate * 100
        combined_score = (0.6 * ping) + (0.3 * loss_percentage * 10) + (0.1 * jitter)
        if loss_rate == 1.0:
            combined_score += 5000

        extended_results_v4.append((ip, port, ping, loss_percentage, jitter, combined_score))

    sorted_results_v4 = sorted(extended_results_v4, key=lambda x: x[5])


    # --- Save IPv4 Results ---
    unique_saved_ips = set() # Keep track of IPs already saved
    for ip, port, ping, loss_p, jitter_val, score in sorted_results_v4:
        if do_you_save == '1':
             # Use the globally set ping_range string
             ping_range_int_v4 = 1000
             try:
                  ping_range_int_v4 = int(ping_range)
             except (ValueError, TypeError):
                  pass # Use default if invalid

             # Condition to save: low loss, valid ping within range, and not already saved
             if loss_p < 5.0 and ping < 999 and ping <= ping_range_int_v4:
                ip_to_save = f"[{ip}]" if need_port == '2' else f"{ip}:{port}" # Format IP/IP:Port based on need_port

                # Check if this specific IP (or IP:Port) has already been added
                # For bpb panel, only save unique IPs. For vahid, duplicates are okay.
                save_key = ip if which == '1' else ip_to_save # Key for uniqueness check

                if which == '1' and save_key in unique_saved_ips:
                    continue # Skip if this IP is already saved for bpb panel

                # Add to save_result based on format
                if which == '1': # bpb (comma)
                    if need_port == '1':
                        save_result.append(f"{ip}:{port},")
                    else:
                        save_result.append(f"{ip},")
                    unique_saved_ips.add(ip) # Add IP to set for bpb
                elif which == '2': # vahid (newline)
                    if need_port == '1':
                        save_result.append(f"{ip}:{port}\n")
                    else:
                        save_result.append(f"{ip}\n")
                    # No uniqueness check needed for vahid format (explicitly requested newline per entry)
                elif which == '3': # with score
                    # Uniqueness check for 'with score' might be desired - let's add it based on IP
                    if ip not in unique_saved_ips:
                        if need_port == '1':
                            save_result.append(f"{ip}:{port} | ping: {ping:.2f} loss: {loss_p:.2f}% jitter: {jitter_val:.2f}\n")
                        else:
                            save_result.append(f"{ip} | ping: {ping:.2f} loss: {loss_p:.2f}% jitter: {jitter_val:.2f}\n")
                        unique_saved_ips.add(ip)


    # --- Display Top IPv4 Results ---
    console.clear()
    table_v4 = Table(show_header=True, title="Top IPv4 Scan Results", header_style="bold blue")
    table_v4.add_column("IP", style="dim", width=15)
    table_v4.add_column("Port", justify="right")
    table_v4.add_column("Ping (ms)", justify="right")
    table_v4.add_column("Packet Loss (%)", justify="right")
    table_v4.add_column("Jitter (ms)", justify="right")
    table_v4.add_column("Score", justify="right")

    for ip, port, ping, loss_p, jitter_val, score in sorted_results_v4[:15]: # Show top 15
        table_v4.add_row(
            ip,
            str(port),
            f"{ping:.2f}",
            f"{loss_p:.2f}%",
            f"{jitter_val:.2f}",
            f"{score:.2f}"
        )
    console.print(table_v4)


    # --- Determine Best IPv4 Result ---
    best_result_v4_tuple = None
    if sorted_results_v4:
         # Find the best result that has low loss and valid ping
         for res in sorted_results_v4:
              ip, port, ping, loss_p, _, score = res
              if loss_p < 5.0 and ping < 999:
                   best_result_v4_tuple = res
                   break # Found the best usable one

    best_result_return = [None, None] # Format to return [IP_String, Port_Int]
    if best_result_v4_tuple:
        ip, port, ping, loss_p, jitter_val, score = best_result_v4_tuple
        console.print(f"\n[bold green]Best IPv4: {ip}:{port} | Ping: {ping:.2f}ms | Loss: {loss_p:.2f}% | Jitter: {jitter_val:.2f}ms | Score: {score:.2f}[/bold green]")
        best_result_return[0] = ip # Just the IP string
        best_result_return[1] = port # Port integer
    else:
        console.print("\n[bold yellow]No suitable IPv4 address found.[/bold yellow]")
        # Fallback? Or return None? Returning None might be safer.

    # --- Save Formatted IPv4 Results ---
    if do_you_save == '1' and save_result:
        # Clean trailing comma for bpb panel
        if which == '1' and save_result and save_result[-1].endswith(','):
             save_result[-1] = save_result[-1][:-1]

        try:
            filepath_v4 = '/storage/emulated/0/result_v4.csv'
            with open(filepath_v4, "w") as f:
                 f.writelines(save_result)
            print(f'IPv4 results saved in {filepath_v4} !')
        except Exception as e:
            print(f"[!] Error saving IPv4 results: {e}")

    return best_result_return # Return [IP_String, Port_Int] or [None, None]


def main2():
    global best_result
    global what # Need 'what' to decide flow
    global WoW_v2 # Need to write to this
    global how_many # Need for loop range
    global polrn_block # Need for config generation
    global isIran # Need for config generation


    def main2_2():
        # Generates one config for the WoW sub link
        global WoW_v2
        global best_result # Use the already scanned best_result
        global polrn_block # Access global
        global what # Access global for noise option

        try:
           # Fetch two sets of keys
           rprint("[bold cyan]Fetching keys for WoW config...[/bold cyan]")
           all_key3 = free_cloudflare_account() # Returns list: [Address, PrivateKey, Reserved, PublicKey]
           time.sleep(1) # Small delay between API calls
           all_key2 = free_cloudflare_account()
           if not all_key3 or not all_key2:
               raise ValueError("Failed to fetch necessary keys.")
           rprint("[bold green]Keys fetched successfully.[/bold green]")

        except Exception as E:
            print(f'[!] Error fetching keys for WoW: {E}')
            print("[!] Cannot proceed without keys. Exiting.")
            exit(1)

        # Use the 'best_result' found by main() or main_v6()
        # Ensure best_result is in the format [IP_String_or_[IP_String], Port_Int]
        endpoint_ip = best_result[0]
        endpoint_port = best_result[1]

        # Handle potential bracket in IPv6 address string: "[2606:4700::...]" -> "2606:4700::..."
        if isinstance(endpoint_ip, str) and endpoint_ip.startswith('[') and endpoint_ip.endswith(']'):
             endpoint_ip = endpoint_ip[1:-1]

        if not endpoint_ip or not endpoint_port:
             print("[!] Error: Best IP/Port not available for WoW config generation.")
             # Fallback to a default endpoint?
             endpoint_ip = "162.159.192.1" # Example default
             endpoint_port = 2408        # Example default
             print(f"[!] Using default endpoint: {endpoint_ip}:{endpoint_port}")
             # Or exit? For now, use default. exit(1)

        # --- Start Building WoW JSON Part ---
        # Remarks include Telegram handle
        remarks = "Tel= arshiacomplus - WoW" # Standard remark

        # Build the first outbound (main warp-out using key3)
        warp_out_settings = {
            "address": ["172.16.0.2/32", all_key3[0]], # Address from key3
            "mtu": 1280,
            "peers": [{
                "endpoint": f"{endpoint_ip}:{endpoint_port}", # Use scanned result
                "publicKey": all_key3[3], # Public key from key3
                # "allowedIPs": ["0.0.0.0/0", "::/0"], # Often needed
                # "preSharedKey": "" # Optional PSK
            }],
            "reserved": all_key3[2], # Reserved from key3
            "secretKey": all_key3[1] # Private key from key3
        }
        # Add noise settings if applicable (what == '14')
        if what == '14':
            warp_out_settings.update({
                "keepAlive": 10,
                "wnoise": "quic",
                "wnoisecount": "10-15",
                "wpayloadsize": "1-8",
                "wnoisedelay": "1-3"
            })

        # Build the second outbound (iran warp-ir using key2)
        # Use a known working Cloudflare IP for the IR hop if needed, or the scanned one?
        # Using a fixed one might be more reliable for the IR hop.
        iran_endpoint_ip = "162.159.192.1" # Example fixed IP for IR hop
        iran_endpoint_port = 2408       # Example fixed Port for IR hop
        warp_ir_settings = {
            "address": ["172.16.0.2/32", all_key2[0]], # Address from key2
            "mtu": 1280,
            "peers": [{
                "endpoint": f"{iran_endpoint_ip}:{iran_endpoint_port}", # Fixed endpoint for IR
                "publicKey": all_key2[3], # Public key from key2
            }],
            "reserved": all_key2[2], # Reserved from key2
            "secretKey": all_key2[1] # Private key from key2
        }
        # Add noise settings if applicable (what == '14')
        if what == '14':
             warp_ir_settings.update({
                 "keepAlive": 10,
                 "wnoise": "quic",
                 "wnoisecount": "10-15",
                 "wpayloadsize": "1-8",
                 "wnoisedelay": "1-3"
             })

        # Build the full V2Ray JSON structure for this config
        config_json = {
            "remarks": remarks,
            "log": {"loglevel": "warning"},
            "dns": {
                "hosts": {
                    "geosite:category-ads-all": "127.0.0.1",
                    "geosite:category-ads-ir": "127.0.0.1",
                    **( {"geosite:category-porn": "127.0.0.1"} if polrn_block == '1' else {} )
                },
                "servers": [
                    "https://dns.cloudflare.com/dns-query", # Cloudflare primary
                    "1.1.1.1",
                    "8.8.8.8",
                    "localhost" # Use system DNS as fallback
                 ],
                 "tag": "dns"
            },
            "inbounds": [
                 {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": False}, "tag": "socks-in"},
                 {"port": 10809, "protocol": "http", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": False}, "tag": "http-in"},
                 {"listen": "127.0.0.1", "port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"}
            ],
            "outbounds": [
                 {"protocol": "wireguard", "settings": warp_out_settings, "streamSettings": {"sockopt": {"dialerProxy": "warp-ir"}}, "tag": "warp-out"}, # warp-out uses warp-ir as proxy
                 {"protocol": "wireguard", "settings": warp_ir_settings, "tag": "warp-ir"}, # warp-ir connects directly
                 {"protocol": "dns", "tag": "dns-out"},
                 {"protocol": "freedom", "settings": {}, "tag": "direct"},
                 {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
            ],
            "policy": {
                 "levels": {"8": {"connIdle": 300, "downlinkOnly": 0, "handshake": 4, "uplinkOnly": 0}}, # Adjusted defaults
                 "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
            },
            "routing": {
                "domainStrategy": "IPIfNonMatch", # AsIs or IPIfNonMatch are common
                "rules": [
                    {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out"},
                    # Route DNS queries to known servers directly if needed, otherwise let warp handle
                    # {"type": "field", "port": 53, "network": "udp", "outboundTag": "dns-out"}, # Example direct DNS rule
                    # Direct Iranian domains/IPs
                    {"type": "field", "domain": ["geosite:category-ir", "domain:.ir"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:ir", "geoip:private"], "outboundTag": "direct"},
                    # Block specific categories
                    {"type": "field", "domain": ["geosite:category-ads-all", "geosite:category-ads-ir", *(["geosite:category-porn"] if polrn_block == '1' else [])], "outboundTag": "block"},
                    # Default traffic through warp-out
                    {"type": "field", "network": "tcp,udp", "outboundTag": "warp-out"}
                ]
            },
            "stats": {}
        }

        # --- Append the generated JSON string to WoW_v2 ---
        # Properly format as JSON string, handle indentation later
        WoW_v2 += json.dumps(config_json) # Add as compact JSON string first


    def main2_1():
        # Generates single V2Ray/Hiddify/Sing-box config (non-sub)
        global best_result
        global what # Access global
        global isIran # Access global
        global polrn_block # Access global

        print("[*] Generating single config...")
        try:
            rprint("[bold cyan]Fetching keys for config...[/bold cyan]")
            all_key = free_cloudflare_account() # [Address, PrivateKey, Reserved, PublicKey]
            if not all_key: raise ValueError("Failed to fetch primary keys.")

            all_key2 = None # For second key pair if needed (WoW Iran or Hiddify)
            if what in ['7', '13'] and isIran == '2': # WoW Germany needs second key pair
                time.sleep(1)
                all_key2 = free_cloudflare_account()
                if not all_key2: raise ValueError("Failed to fetch secondary keys for WoW Germany.")
            elif what in ['2', '3', '15', '16']: # Hiddify/Sing-box needs second key pair
                 time.sleep(1)
                 all_key2 = free_cloudflare_account()
                 if not all_key2: raise ValueError("Failed to fetch secondary keys for Hiddify/Sing-box.")

            rprint("[bold green]Keys fetched successfully.[/bold green]")

        except Exception as E:
            print(f'[!] Error fetching keys: {E}')
            exit(1)

        # Handle endpoint selection
        endpoint_ip = None
        endpoint_port = None

        if what in ['3', '16']: # Manual IP input required
            print("\033[0m") # Reset color
            enter_ip = Prompt.ask('Enter IP:Port (or press Enter for default [162.159.195.166:908]): ', default="162.159.195.166:908")
            try:
                if ':' not in enter_ip: raise ValueError("Invalid format, missing colon.")
                temp_ip, temp_port = enter_ip.rsplit(':', 1) # Split only on the last colon
                # Basic validation (improve if needed)
                socket.inet_pton(socket.AF_INET, temp_ip) # Check if valid IPv4
                endpoint_ip = temp_ip
                endpoint_port = int(temp_port)
                if not (0 < endpoint_port < 65536): raise ValueError("Invalid port number")
                best_result = [endpoint_ip, endpoint_port] # Update best_result with manual input
            except Exception as e:
                 print(f"[!] Invalid IP:Port format: {e}. Using default.")
                 best_result = ["162.159.195.166", 908]
                 endpoint_ip, endpoint_port = best_result
        else:
            # Use the result from main() scan
            if not best_result or not best_result[0] or not best_result[1]:
                 print("[!] Error: IP Scan result not available. Exiting.")
                 exit(1)
            endpoint_ip = best_result[0]
            endpoint_port = best_result[1]
             # Handle potential brackets in IPv6 string from scan result
            if isinstance(endpoint_ip, str) and endpoint_ip.startswith('[') and endpoint_ip.endswith(']'):
                 endpoint_ip = endpoint_ip[1:-1]


        # --- Generate Config Based on 'what' ---
        output_config = ""
        os.system('clear')

        if what in ['7', '13']: # WoW for V2Ray/MahsaNG
            rprint(f"[bold cyan]Generating WoW config for V2Ray/MahsaNG (Noise: {'Yes' if what=='13' else 'No'})...[/bold cyan]")
            # Build V2Ray JSON structure
            wow_config = {
                "remarks": f"Tel= arshiacomplus - {'WoW Noise' if what == '13' else 'WoW'} - {'GER' if isIran == '2' else 'IR'}",
                "log": {"loglevel": "warning"},
                 "dns": { # Simplified DNS for WoW
                    "servers": ["1.1.1.1", "8.8.8.8", "localhost"],
                    "hosts": {
                        "geosite:category-ads-all": "127.0.0.1",
                        **( {"geosite:category-porn": "127.0.0.1"} if polrn_block == '1' else {} )
                    },
                     "tag": "dns"
                 },
                "inbounds": [
                     {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}, "tag": "socks-in"},
                     {"port": 10809, "protocol": "http", "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}, "tag": "http-in"}
                ],
                "outbounds": [], # Populate based on isIran
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [
                        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}, # Always direct private IPs
                        # Block rules
                        {"type": "field", "domain": ["geosite:category-ads-all", *(["geosite:category-porn"] if polrn_block == '1' else [])], "outboundTag": "block"},
                    ]
                },
                "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
                "stats": {}
            }

            # Define peers
            peer1_settings = {
                 "endpoint": f"{endpoint_ip}:{endpoint_port}",
                 "publicKey": all_key[3],
                 # "allowedIPs": ["0.0.0.0/0", "::/0"],
                 # "preSharedKey": ""
            }
            # Main outbound settings using key1
            outbound1_settings = {
                "address": ["172.16.0.2/32", all_key[0]],
                "mtu": 1280,
                "peers": [peer1_settings],
                "reserved": all_key[2],
                "secretKey": all_key[1]
            }
            if what == '13': # Add noise if '13'
                 outbound1_settings.update({
                     "keepAlive": 10, "wnoise": "quic", "wnoisecount": "10-15",
                     "wpayloadsize": "1-8", "wnoisedelay": "1-3"
                 })


            if isIran == '1': # Iran IP (Single Warp)
                 wow_config["outbounds"].extend([
                      {"protocol": "wireguard", "settings": outbound1_settings, "tag": "warp"},
                      {"protocol": "freedom", "settings": {}, "tag": "direct"},
                      {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
                 ])
                 # Routing rules for single warp
                 wow_config["routing"]["rules"].extend([
                     {"type": "field", "domain": ["geosite:category-ir", "domain:.ir"], "outboundTag": "direct"},
                     {"type": "field", "ip": ["geoip:ir"], "outboundTag": "direct"},
                     {"type": "field", "network": "tcp,udp", "outboundTag": "warp"} # Default route
                 ])
            else: # isIran == '2' (Germany - WoW setup)
                 if not all_key2: # Check if second key exists
                      print("[!] Error: Secondary key missing for WoW Germany setup.")
                      exit(1)
                 # Define peer and outbound for the IR hop using key2
                 peer2_settings = {
                      "endpoint": f"{iran_endpoint_ip}:{iran_endpoint_port}", # Fixed IR endpoint
                      "publicKey": all_key2[3],
                 }
                 outbound2_settings = {
                      "address": ["172.16.0.2/32", all_key2[0]],
                      "mtu": 1280,
                      "peers": [peer2_settings],
                      "reserved": all_key2[2],
                      "secretKey": all_key2[1]
                 }
                 if what == '13': # Add noise to IR hop as well if '13'
                     outbound2_settings.update({
                          "keepAlive": 10, "wnoise": "quic", "wnoisecount": "10-15",
                          "wpayloadsize": "1-8", "wnoisedelay": "1-3"
                     })

                 wow_config["outbounds"].extend([
                      {"protocol": "wireguard", "settings": outbound1_settings, "streamSettings": {"sockopt": {"dialerProxy": "warp-ir"}}, "tag": "warp-out"}, # Main outbound proxied
                      {"protocol": "wireguard", "settings": outbound2_settings, "tag": "warp-ir"}, # IR hop direct
                      {"protocol": "freedom", "settings": {}, "tag": "direct"},
                      {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
                 ])
                 # Routing rules for WoW setup
                 wow_config["routing"]["rules"].extend([
                      {"type": "field", "domain": ["geosite:category-ir", "domain:.ir"], "outboundTag": "direct"},
                      {"type": "field", "ip": ["geoip:ir"], "outboundTag": "direct"},
                      {"type": "field", "network": "tcp,udp", "outboundTag": "warp-out"} # Default route via main outbound
                 ])

            output_config = json.dumps(wow_config, indent=2) # Pretty print JSON

        elif what in ['2', '3', '15', '16']: # Hiddify / Sing-box (Old style)
             if not all_key2: # Ensure second key is available
                  print("[!] Error: Secondary key missing for Hiddify/Sing-box setup.")
                  exit(1)
             rprint(f"[bold cyan]Generating WireGuard config for Hiddify/Sing-box (Fake Packets: {'Yes' if what in ['2', '3'] else 'No'})...[/bold cyan]")
             # Build Sing-box JSON structure
             hiddify_config = {
                 "outbounds": [
                     { # IR Hop (using key1) - Tagged as Warp-IR
                         "type": "wireguard",
                         "tag": "Tel=@arshiacomplus Warp-IR1",
                         "local_address": ["172.16.0.2/32", all_key[0]],
                         "private_key": all_key[1],
                         "peer_public_key": all_key[3], # Peer is Cloudflare
                         "server": endpoint_ip,
                         "server_port": endpoint_port,
                         "reserved": all_key[2],
                         "mtu": 1280,
                         **( {"fake_packets":"1-3", "fake_packets_size":"10-30", "fake_packets_delay":"10-30", "fake_packets_mode":"m4"} if what in ['2','3'] else {} )
                     },
                     { # Main Hop (using key2) - Tagged as Warp-Main, detoured through IR
                         "type": "wireguard",
                         "tag": "Tel=@arshiacomplus Warp-Main1",
                         "detour": "Tel=@arshiacomplus Warp-IR1", # Route through the IR hop
                         "local_address": ["172.16.0.2/32", all_key2[0]],
                         "private_key": all_key2[1],
                         "peer_public_key": all_key2[3], # Peer is Cloudflare
                         "server": endpoint_ip, # Use same endpoint for simplicity, detour handles routing
                         "server_port": endpoint_port,
                         "reserved": all_key2[2],
                         "mtu": 1330, # Slightly larger MTU for main hop? Check if needed. 1280 is safer.
                          **( {"fake_packets_mode":"m4"} if what in ['2','3'] else {} ) # Only mode needed for detour?
                     }
                 ]
             }
             output_config = json.dumps(hiddify_config, indent=2) # Pretty print JSON

        else:
             print(f"[!] Error: Unsupported configuration type '{what}' in main2_1.")
             exit(1)

        # Print the generated configuration
        print("\n" + "="*20 + " Generated Config " + "="*20 + "\n")
        rprint(output_config)
        print("\n" + "="*58 + "\n")

        if what == "3" or what == "16": # Exit after manual IP entry configs
            exit()


    # --- Main logic for main2 ---
    if what in ['8', '14']: # WoW Sub Link Generation
        rprint("[bold green]Generating WoW Subscription Link...[/bold green]")
        WoW_v2 = "" # Reset WoW_v2 string
        # Need 'how_many' - assume it's set globally or passed
        if 'how_many' not in globals() or not isinstance(how_many, int) or how_many < 1:
             print("[!] Error: 'how_many' configs not specified for sub link.")
             exit(1)

        # Scan for the best IP first
        print("[*] Scanning for the best IP before generating sub link configs...")
        best_result = main() # Run scan (main handles v4/v6 choice internally now)
        if not best_result or not best_result[0] or not best_result[1]:
             print("[!] Failed to find a suitable IP via scan. Cannot generate subscription link.")
             exit(1)
        print(f"[*] Using best IP: {best_result[0]}:{best_result[1]} for all configs in the sub link.")

        # Generate 'how_many' configs
        configs_list = []
        for n in range(how_many):
             print(f"\n--- Generating config {n+1}/{how_many} ---")
             WoW_v2 = "" # Reset for each config part generation
             main2_2() # Generates the JSON string part and appends to WoW_v2
             try:
                 # Parse the generated JSON string back into a dict object
                 config_dict = json.loads(WoW_v2)
                 configs_list.append(config_dict) # Add the dictionary to the list
             except json.JSONDecodeError as e:
                  print(f"[!] Error parsing generated JSON for config {n+1}: {e}")
                  print(f"[!] Faulty JSON string part: {WoW_v2}")
                  # Decide whether to skip or exit
                  print("[!] Skipping this config due to error.")
                  # continue
                  exit(1) # Exit if one config fails, safer for sub link generation


        os.system('clear')
        if configs_list:
             # Upload the list of config dictionaries as a single JSON array
             final_json_output = json.dumps(configs_list, indent=2) # Pretty print the final list
             # print(final_json_output) # Optional: print before upload
             upload_to_bashupload(final_json_output)
        else:
             print("[!] No valid configurations were generated for the subscription link.")
        exit()

    else: # Handle single config generation cases
        if what not in ['3', '16']: # Run scan only if not manual IP mode
            best_result = main() # Run scan (handles v4/v6 choice)
            if not best_result or not best_result[0] or not best_result[1]:
                 print("[!] IP Scan failed or found no suitable IP. Exiting.")
                 exit(1)

        # Call main2_1 to generate and print the single config
        main2_1()


def main3():
    # Generates Hiddify/Sing-box Subscription Link
    global best_result
    global wire_config_temp # Holds the accumulating JSON string parts
    global wire_c # Counter for tags
    global wire_p # Flag to check if it's the first config
    global what # Access global for fake packet option
    global how_many # Access global for loop count

    # Scan for IP only on the first run (wire_p == 0)
    if wire_p == 0:
         print("[*] Scanning for the best IP for the subscription link...")
         try:
             best_result = main() # Run scan (handles v4/v6)
             if not best_result or not best_result[0] or not best_result[1]:
                  raise ConnectionError("IP Scan failed to find a suitable IP.")
             print(f"[*] Using best IP: {best_result[0]}:{best_result[1]} for all configs.")
         except Exception as e:
             print(f"\033[91m[!] Error during initial IP scan: {e}\033[0m")
             print("[!] Try again or choose an option without IP scanning.")
             exit(1)

    # --- Generate one pair of outbounds for the subscription link ---
    os.system('clear')
    print(f"[*] Please wait, generating config part: {wire_c}/{how_many}")
    print('\033[0m') # Reset color

    try:
        rprint("[bold cyan]Fetching keys...[/bold cyan]")
        all_key = free_cloudflare_account() # [Address, PrivateKey, Reserved, PublicKey]
        time.sleep(1)
        all_key2 = free_cloudflare_account() # Second pair
        if not all_key or not all_key2:
            raise ValueError("Failed to fetch necessary keys.")
        rprint("[bold green]Keys fetched successfully.[/bold green]")
    except Exception as e:
         print(f"[!] Error fetching keys for config part {wire_c}: {e}")
         # Decide: skip this config part or exit? Exiting is safer.
         print("[!] Exiting due to key fetching error.")
         exit(1)

    # Endpoint details from the initial scan (or subsequent runs use the same)
    endpoint_ip = best_result[0]
    endpoint_port = best_result[1]
    # Handle potential IPv6 brackets
    if isinstance(endpoint_ip, str) and endpoint_ip.startswith('[') and endpoint_ip.endswith(']'):
         endpoint_ip = endpoint_ip[1:-1]

    # Build the JSON for the two outbounds (IR and Main)
    outbound_ir = {
        "type": "wireguard",
        "tag": f"Tel=@arshiacomplus Warp-IR{wire_c}",
        "local_address": ["172.16.0.2/32", all_key[0]],
        "private_key": all_key[1],
        "peer_public_key": all_key[3],
        "server": endpoint_ip,
        "server_port": endpoint_port,
        "reserved": all_key[2],
        "mtu": 1280,
        **( {"fake_packets":"1-3", "fake_packets_size":"10-30", "fake_packets_delay":"10-30", "fake_packets_mode":"m4"} if what != '17' else {} ) # Add fake packets if not '17'
    }
    outbound_main = {
        "type": "wireguard",
        "tag": f"Tel=@arshiacomplus Warp-Main{wire_c}",
        "detour": f"Tel=@arshiacomplus Warp-IR{wire_c}",
        "local_address": ["172.16.0.2/32", all_key2[0]],
        "private_key": all_key2[1],
        "peer_public_key": all_key2[3],
        "server": endpoint_ip,
        "server_port": endpoint_port,
        "reserved": all_key2[2],
        "mtu": 1280, # Keep MTU consistent and safe
         **( {"fake_packets_mode":"m4"} if what != '17' else {} ) # Add fake packet mode if not '17'
    }

    # Convert these dicts to JSON strings
    # Add comma prefix if not the first element (wire_p == 1)
    comma_prefix = "," if wire_p == 1 else ""
    try:
        # Generate compact JSON for accumulation
        json_part = comma_prefix + json.dumps(outbound_ir) + "," + json.dumps(outbound_main)
    except Exception as json_err:
         print(f"[!] Error converting config part {wire_c} to JSON: {json_err}")
         # Skip or exit? Exit is safer.
         print("[!] Exiting due to JSON conversion error.")
         exit(1)


    # Accumulate the JSON string part
    wire_config_temp += json_part
    wire_c += 1 # Increment counter
    wire_p = 1 # Set flag indicating at least one part has been added


    # Check if this is the last config part to generate
    # Use 'i' which should be the loop variable from the caller (__main__)
    # Need to ensure 'i' is accessible or pass it as an argument.
    # Assuming 'i' is accessible via globals (less ideal) or passed.
    # Let's refine this: main3 should know its index. Modify the loop in __main__.

    # --- This check needs to happen in the loop calling main3 ---
    # --- See modification in the __main__ block ---
    # if i == int(how_many)-1: # 'i' is the loop index (0 to how_many-1)
    #     os.system('clear')
    #     final_sub_json = f'''{{
    #         "outbounds": [{wire_config_temp}]
    #     }}'''
    #     print("[*] All config parts generated. Uploading final subscription link...")
    #     # Use pretty print for the final upload if desired, or compact
    #     try:
    #         # Validate and potentially pretty-print the final JSON
    #         final_data_obj = json.loads(final_sub_json)
    #         final_json_pretty = json.dumps(final_data_obj, indent=2)
    #         upload_to_bashupload(final_json_pretty)
    #     except json.JSONDecodeError as e:
    #          print(f"[!] Error: Final generated JSON is invalid: {e}")
    #          print("[!] Cannot upload. Please check the generated parts.")
    #          # print(f"[-] Accumulated JSON string: [{wire_config_temp}]") # Debug output
    #     except Exception as upload_err:
    #          print(f"[!] Error during upload: {upload_err}")


def generate_wireguard_url(config_dict, endpoint):
    """Generates a WireGuard URL for V2RayNG/MahsaNG."""
    global what # Access 'what' to check for noise options

    # Validate input dictionary
    required_keys = ['PrivateKey', 'PublicKey', 'Reserved', 'Address']
    if not all(key in config_dict and config_dict[key] is not None for key in required_keys):
        print("[!] Incomplete configuration dictionary provided to generate_wireguard_url.")
        return None
    if not isinstance(config_dict['Reserved'], list) or len(config_dict['Reserved']) != 3:
         print(f"[!] Invalid 'Reserved' format: {config_dict['Reserved']}. Expected list of 3 integers.")
         # Try to use a default if format is wrong? Or fail? Failing is safer.
         # config_dict['Reserved'] = [222, 6, 184] # Example default
         return None


    # Format reserved list for URL encoding: comma-separated string
    reserved_str = ','.join(map(str, config_dict['Reserved']))

    # Base URL structure
    # wireguard://<PrivateKey>@<Endpoint>?address=<LocalAddress1>,<LocalAddress2>&publickey=<PeerPublicKey>&reserved=<Reserved>...#Remark
    base_url = f"wireguard://{urlencode(config_dict['PrivateKey'])}@{endpoint}"

    # Parameters dictionary
    params = {
        "address": f"172.16.0.2/32,{urlencode(config_dict['Address'])}",
        "publickey": urlencode(config_dict['PublicKey']),
        "reserved": urlencode(reserved_str),
        "mtu": "1280" # Standard MTU
    }

    # Add noise parameters if 'what' is '11' or '12'
    if what in ['11', '12']:
        params.update({
            "wnoise": "quic",
            "keepalive": "5", # Note: keepalive seems non-standard for WG URL, might be ignored
            "wpayloadsize": "1-8",
            "wnoisedelay": "1-3",
            "wnoisecount": "15" # Note: wnoisecount also non-standard for URL
            # MTU is already set, potentially adjust if noise requires it? 1280 is usually fine.
        })

    # Construct query string
    query_string = "&".join([f"{key}={value}" for key, value in params.items()])

    # Final URL
    wireguard_urll = f"{base_url}?{query_string}#Tel=%20%40arshiacomplus%20wire" # URL Encoded remark

    return wireguard_urll

def start_menu():
    os.system('clear')
    check_ipv = check_ipv6()
    rprint(f'IPv4 Status : {check_ipv[0]}')
    rprint(f'IPv6 Status : {check_ipv[1]}\n')

    options = {
        "1": "Scan IPs (Save Results)",
        "2": "WireGuard for Hiddify/Sing-box (Scan IP)",
        "3": "WireGuard for Hiddify/Sing-box (Manual IP)",
        "4": "WireGuard for Hiddify/Sing-box (Subscription Link)",
        "5": "WireGuard URL for V2RayNG/MahsaNG (No Noise, Scan IP)",
        "6": "WireGuard URL for V2RayNG/MahsaNG (No Noise, Manual IP)",
        "7": "WoW for V2Ray/MahsaNG (No Noise, Scan IP)",
        "8": "WoW for V2Ray/MahsaNG (No Noise, Subscription Link)",
        "9": "Add/Delete Termux Shortcut",
       "10": "Generate wireguard.conf file (Scan IP)",
       "11": "WireGuard URL for V2RayNG/NikaNG (With Noise, Scan IP)",
       "12": "WireGuard URL for V2RayNG/NikaNG (With Noise, Manual IP)",
       "13": "WoW for V2Ray/NikaNG (With Noise, Scan IP)",
       "14": "WoW for V2Ray/NikaNG (With Noise, Subscription Link)",
       # Options 15, 16, 17 seem redundant with 2, 3, 4 - using the newer labels
       # "15": "WireGuard for Sing-box/Hiddify | old | (Scan IP)", # Same as 2
       # "16": "WireGuard for Sing-box/Hiddify | old | (Manual IP)", # Same as 3
       # "17": "WireGuard for Sing-box/Hiddify | old | (Sub Link)", # Same as 4
        "00": "Info",
        "0": "Exit"
    }

    rprint("[bold red]Script by Telegram= @arshiacomplus[/bold red]")
    for key, value in options.items():
        # Use cleaner formatting
        rprint(f" [bold yellow]{key:>2}[/bold yellow]: {value}") # Right-align key
    what_choice = Prompt.ask("Choose an option", choices=list(options.keys()), default="0")
    return what_choice

def get_number_of_configs():
    while True:
        try:
            # Clarify purpose
            num_str = Prompt.ask('\nHow many configs for the subscription link? (2 to 10 recommended): ', default="4")
            how_many_cfgs = int(num_str)
            # Allow more configs if needed, but warn
            if 2 <= how_many_cfgs <= 10:
                break
            elif how_many_cfgs > 10:
                 rprint("[yellow]Warning: Generating a large number of configs might take time and API calls.[/yellow]")
                 confirm = Prompt.ask(f"Are you sure you want {how_many_cfgs} configs?", choices=["y", "n"], default="n")
                 if confirm.lower() == 'y':
                     break
            else:
                 print("[!] Please enter a number of 2 or more.")
        except ValueError:
            console.print("[bold red]Please enter a valid number![/bold red]", style="red")
    return how_many_cfgs

def gojo_goodbye_animation():
    # Simple text animation
    frames  = [
        "\n\033[94m(^_^)/ Bye!...\033[0m",  # Blue
        "\n\033[92m(^_^)/ Bye Bye!!...\033[0m",  # Green
        "\n\033[93m(^_^)/ Bye Bye!!!...\033[0m" , # Yellow
    ]

    for frame in frames:
        # os.system('cls' if os.name == 'nt' else 'clear') # Clearing might be too flashy
        print(frame, end='\r') # Use carriage return for overwrite effect
        time.sleep(0.7)
    print("\n") # Newline after animation

# --- Main Execution Block (__main__) ---
if __name__ == "__main__":
    # Initialize global variables that might be set by options
    what = None # User's main choice
    do_you_save = '2' # Default: Don't save scan results
    which = 'n' # Default format for saving
    need_port = '1' # Default: Save port in results
    how_many = 0 # Default number of configs for subs
    polrn_block = '2' # Default: Don't block porn
    isIran = '1' # Default: Use IR routing for WoW

    try:
        what = start_menu()

        if what == '1': # Scan IPs and Save
            do_you_save = input_p('Save scan results to CSV?\n', {"1": 'Yes', "2": "No"})
            if do_you_save == '1':
                # Check storage permission early
                print("[*] Checking storage access...")
                if os.access('/storage/emulated/0/', os.W_OK):
                     print("[+] Storage access OK.")
                else:
                     print("[!] Storage access denied or not set up. Attempting setup...")
                     os.system('termux-setup-storage')
                     # Wait a moment and check again
                     time.sleep(3)
                     if not os.access('/storage/emulated/0/', os.W_OK):
                          print("[!] Failed to get storage access. Cannot save file.")
                          do_you_save = '2' # Force disable saving

            if do_you_save == '1': # Ask format only if saving is enabled
                which = input_p('Choose save format:\n ', {'1': 'BPB Panel (IP1,IP2,... or IP:Port1,IP:Port2,...)',
                                                       '2': 'Vahid Panel (IP/IP:Port per line)',
                                                       '3': 'Detailed (IP/IP:Port | ping loss jitter)',
                                                       '4': 'Clean Existing (Remove scores)'})
                if which != '4':
                    need_port = input_p('Include port in saved results?\n ', {'1': 'Yes (IP:Port)', '2': 'No (IP only)'})

                if which == '4': # Clean existing file
                    clean_which = input_p('Select format for CLEANED file:\n ', {'1': 'BPB (Comma separated)', '2': 'Vahid (Newline separated)'})
                    source_file = '/storage/emulated/0/result_v4.csv' # Assume cleaning v4 by default
                    source_v6 = '/storage/emulated/0/result_v6.csv'
                    target_file = '/storage/emulated/0/clean_result.csv'
                    cleaned_count = 0
                    print(f"[*] Attempting to clean {source_file}...")
                    try:
                        if not os.path.exists(source_file) and os.path.exists(source_v6):
                             source_file = source_v6 # Clean v6 file if v4 doesn't exist
                             print(f"[*] V4 file not found, cleaning {source_file} instead.")
                        elif not os.path.exists(source_file):
                             print(f"[!] Source file {source_file} not found. Cannot clean.")
                             exit()


                        with open(source_file, 'r') as f_in, open(target_file, 'w') as f_out:
                             lines = f_in.readlines()
                             output_lines = []
                             for line in lines:
                                  line = line.strip()
                                  if not line: continue # Skip empty lines
                                  # Try to extract IP or IP:Port before the '|'
                                  parts = line.split('|', 1)
                                  ip_part = parts[0].strip()
                                  if ip_part: # Ensure we got something
                                       output_lines.append(ip_part)
                                       cleaned_count += 1

                             # Join based on selected format
                             if clean_which == '1': # Comma separated
                                  f_out.write(','.join(output_lines))
                             else: # Newline separated
                                  f_out.write('\n'.join(output_lines))

                        print(f'[+] Cleaned {cleaned_count} entries. Saved to {target_file} !')
                    except Exception as e:
                        print(f"[!] Error during cleaning: {e}")
                    exit() # Exit after cleaning

            # Run the main scan function (handles v4/v6 choice internally)
            main()

        elif what in ['2', '3', '7', '13']: # Single Config Generation
            # Options specific to WoW
            if what in ['7', '13']:
                polrn_block = input_p('Block p*rn sites?\n', {"1": "Yes", "2": "No"})
                isIran = input_p('Routing Type:\n', {"1": "IR (Faster, Warp Direct)", "2": "GER (Slower, WoW Setup)"})

            # Call main2 (handles scan or manual IP based on 'what')
            main2()

        elif what in ['4', '8', '17']: # Subscription Link Generation
             # Option 17 is handled like 4
             what = '4' if what == '17' else what # Consolidate logic

             how_many = get_number_of_configs()

             if what == '8': # WoW Sub Link specific options
                 polrn_block = input_p('Block p*rn sites in configs?\n', {"1": "Yes", "2": "No"})
                 # Note: WoW Sub link always uses the GER/WoW structure currently in main2_2
                 print("[*] WoW Subscription link will use WoW (GER-style) routing.")

             # Call main2 for WoW sub ('8') or main3 loop for Hiddify sub ('4')
             if what == '8':
                 main2() # main2 handles the loop and upload for WoW sub link now
             else: # what == '4'
                # Reset accumulators for main3 loop
                wire_config_temp = ""
                wire_c = 1
                wire_p = 0
                # Loop calling main3
                for i in range(how_many):
                     main3() # Generates one part, accumulates in wire_config_temp

                     # --- Upload logic moved here from main3 ---
                     if i == how_many - 1: # Check if it's the last iteration
                          os.system('clear')
                          final_sub_json = f'''{{
                              "outbounds": [{wire_config_temp}]
                          }}'''
                          print("[*] All config parts generated. Uploading final subscription link...")
                          try:
                               # Validate final JSON
                               final_data_obj = json.loads(final_sub_json)
                               final_json_pretty = json.dumps(final_data_obj, indent=2)
                               # print(final_json_pretty) # Optional debug print
                               upload_to_bashupload(final_json_pretty)
                          except json.JSONDecodeError as e:
                               print(f"[!] Error: Final generated subscription JSON is invalid: {e}")
                               print(f"[-] Accumulated JSON string approx: [{wire_config_temp[:200]}...]") # Show beginning
                          except Exception as upload_err:
                               print(f"[!] Error during upload: {upload_err}")


        elif what in ['5', '6', '11', '12']: # WireGuard URL Generation
            endpoint_ip_str = None # Combined IP:Port string
            if what in ['5', '11']: # Needs scan
                print("[*] Scanning for best IP for WireGuard URL...")
                endpoint_ip_best_result = main() # Scan returns [IP, Port] or [None, None]
                if endpoint_ip_best_result and endpoint_ip_best_result[0] and endpoint_ip_best_result[1]:
                     ip_res = endpoint_ip_best_result[0]
                     # Handle IPv6 brackets for endpoint string
                     if isinstance(ip_res, str) and ip_res.startswith('[') and ip_res.endswith(']'):
                          ip_res = ip_res[1:-1] # Remove brackets for URL endpoint part
                     endpoint_ip_str = f"{ip_res}:{endpoint_ip_best_result[1]}"
                else:
                     print("[!] Scan failed to find IP. Cannot generate URL.")
                     exit(1)
            else: # Manual IP input
                endpoint_ip_str = Prompt.ask('Enter IP:Port (e.g., 1.1.1.1:878 or 2606::1:878): ', default="162.159.195.166:878")
                 # Basic validation could be added here

            rprint("[bold green]Please wait, generating WireGuard URL...[/bold green]")
            try:
                # Fetch keys using appropriate API method (User selects via 'api' global)
                config_dictionary = fetch_config_from_api()
                if not config_dictionary:
                     raise ValueError("Failed to fetch keys from API.")

                wireguard_url = generate_wireguard_url(config_dictionary, endpoint_ip_str)
                if wireguard_url:
                    os.system('clear')
                    print("\n" + "="*20 + " WireGuard URL " + "="*20 + "\n")
                    rprint(f"[bold cyan]{wireguard_url}[/bold cyan]")
                    print("\n" + "="*55 + "\n")
                    # Optionally offer to save to file or QR code
                else:
                    print("[!] Failed to generate WireGuard URL.")
            except Exception as E:
                print(f'[!] Error during WireGuard URL generation: {E}')
                exit(1)


        elif what == '9': # Shortcut Management
            bashrc_path = '/data/data/com.termux/files/usr/etc/bash.bashrc'
            bak_path = bashrc_path + '.bak'
            shortcut_marker = "# WarpScanner Shortcut Added by Script"
            shortcut_exists = False

            # Check if bashrc exists
            if not os.path.exists(bashrc_path):
                 print(f"[!] Error: Termux bashrc file not found at {bashrc_path}")
                 exit(1)

            # Check if shortcut already exists (by marker or backup file)
            if os.path.exists(bak_path):
                 shortcut_exists = True
                 print("[*] Backup file found, assuming shortcut exists.")
            else:
                 try:
                     with open(bashrc_path, 'r') as f:
                          if shortcut_marker in f.read():
                               shortcut_exists = True
                               print("[*] Shortcut marker found in bashrc.")
                 except Exception as e:
                      print(f"[!] Error reading bashrc: {e}")

            if shortcut_exists:
                delete_choice = input_p('Shortcut already exists. Delete it?', {"1": "Yes", "2": "No"})
                if delete_choice == '1':
                    try:
                        if os.path.exists(bak_path):
                            # Restore from backup
                            os.system(f'mv "{bak_path}" "{bashrc_path}"')
                            print("[+] Shortcut removed by restoring backup.")
                        else:
                             # Remove manually added lines (more risky)
                             print("[!] Backup file not found. Attempting manual removal (might be incomplete)...")
                             temp_path = bashrc_path + ".tmp"
                             with open(bashrc_path, 'r') as f_in, open(temp_path, 'w') as f_out:
                                  in_shortcut_block = False
                                  for line in f_in:
                                       if line.strip() == shortcut_marker:
                                            in_shortcut_block = True
                                            continue # Skip marker line
                                       if in_shortcut_block and line.strip() == "}": # End of function
                                            in_shortcut_block = False
                                            continue # Skip closing brace
                                       if not in_shortcut_block:
                                            f_out.write(line)
                             os.system(f'mv "{temp_path}" "{bashrc_path}"')
                             print("[+] Attempted manual removal. Please check your bashrc.")

                    except Exception as e:
                         print(f"[!] Error removing shortcut: {e}")
            else:
                # Add shortcut
                while True:
                    name = Prompt.ask("\nEnter a shortcut name (e.g., 'warp'): ")
                    if name and not name.isdigit() and ' ' not in name and '(' not in name and ')' not in name:
                         break
                    else:
                         console.print("\n[bold red]Invalid name. Use letters, no numbers/spaces/parentheses.[/bold red]")

                # Create backup first
                try:
                     os.system(f'cp "{bashrc_path}" "{bak_path}"')
                     print(f"[*] Backup created: {bak_path}")
                except Exception as e:
                     print(f"[!] Warning: Failed to create backup: {e}")


                # Define the shortcut function text
                # Ensure the command fetches and executes the *latest* install script
                script_url = "https://raw.githubusercontent.com/arshiacomplus/WarpScanner/main/install.sh"
                shortcut_text = f'''

{shortcut_marker}
{name}() {{
    echo "Running WarpScanner script..."
    bash <(curl -fsSL {script_url})
    echo "Script finished."
}}
'''
                # Append to bashrc
                try:
                    with open(bashrc_path, 'a') as f:
                        f.write(shortcut_text)
                    rprint(f"\n[bold green]Shortcut '{name}' added successfully![/bold green]")
                    rprint(f"[bold yellow]Restart Termux and type '{name}' to run the script.[/bold yellow]")
                except Exception as e:
                    print(f"[!] Error writing to bashrc: {e}")
                    print("[!] Restoring from backup if possible...")
                    if os.path.exists(bak_path):
                         os.system(f'mv "{bak_path}" "{bashrc_path}"') # Restore on error


        elif what == '10': # Generate wireguard.conf
            print("[*] Scanning for best IP for wireguard.conf...")
            endpoint_ip_best_result = main() # Scan returns [IP, Port]
            if not endpoint_ip_best_result or not endpoint_ip_best_result[0] or not endpoint_ip_best_result[1]:
                 print("[!] Scan failed. Cannot generate config file.")
                 exit(1)

            endpoint_ip = endpoint_ip_best_result[0]
            endpoint_port = endpoint_ip_best_result[1]
            # Handle IPv6 brackets for endpoint
            if isinstance(endpoint_ip, str) and endpoint_ip.startswith('[') and endpoint_ip.endswith(']'):
                 endpoint_ip_formatted = endpoint_ip # Keep brackets for conf endpoint
            else:
                 endpoint_ip_formatted = endpoint_ip # IPv4 doesn't need brackets

            try:
                rprint("[bold cyan]Fetching keys for config file...[/bold cyan]")
                # Use free_cloudflare_account which returns the list format needed here
                all_key_list = free_cloudflare_account() # [Address, PrivateKey, Reserved, PublicKey]
                if not all_key_list: raise ValueError("Failed to fetch keys.")
                rprint("[bold green]Keys fetched successfully.[/bold green]")
            except Exception as E:
                print(f'[!] Error fetching keys: {E}')
                exit(1)

            conf_name_input = Prompt.ask('\nEnter config file name (e.g., warp_mci) [Default: acpwire]: ', default='acpwire')
            conf_filename = conf_name_input.strip().replace(" ", "_") + ".conf" # Sanitize name
            conf_path = '/storage/emulated/0/' + conf_filename

            # Check storage access
            if not os.access('/storage/emulated/0/', os.W_OK):
                 print("[!] Storage write access denied. Attempting setup...")
                 os.system('termux-setup-storage')
                 time.sleep(3)
                 if not os.access('/storage/emulated/0/', os.W_OK):
                      print("[!] Failed to get storage access. Cannot save config file.")
                      exit(1)

            # Create config content
            conf_content = f"""[Interface]
PrivateKey = {all_key_list[1]}
Address = 172.16.0.2/32, {all_key_list[0]}
DNS = 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = {all_key_list[3]}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint_ip_formatted}:{endpoint_port}
# Reserved = {all_key_list[2]} # Reserved is usually not part of standard WG conf
"""
            # Write to file
            try:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                rprint(f'\n[bold green]Configuration saved to: {conf_path}[/bold green]')
            except Exception as e:
                print(f"[!] Error writing config file: {e}")


        elif what == '00': # Info
            info()

        elif what == '0': # Exit
            gojo_goodbye_animation()
            console.print("[bold magenta]Exiting... Goodbye![/bold magenta]")
            exit()

        else: # Handle potentially invalid choices if Prompt allows non-listed input
            print(f"[!] Invalid choice: {what}")

    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user.")
        gojo_goodbye_animation()
    except Exception as main_err:
        import traceback
        print("\n[!] An unexpected error occurred in the main execution block:")
        print(traceback.format_exc())
    finally:
         print("\n[*] Script finished.")

