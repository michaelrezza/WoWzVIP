# -*- coding: utf-8 -*-
# Author: Arshia(https://github.com/arshiacomplus)
# Warp Scanner in python with requests module
# Version: 1.7 (Modified with QR Code and Auto-Dependency Install)

import datetime
import json
import os
import random
import string
import subprocess # Added for running pip
import sys      # Added for checking platform and exiting
import time     # Added for sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

# --- Dependency Installation ---
def install_package(package):
    """Installs a package using pip."""
    try:
        print(f"[*] Attempting to install {package}...")
        # Ensure pip is called correctly, especially in virtual environments
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"[+] {package} installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error installing {package}: {e}")
        # Adjusted message for qrcode[pil]
        package_name_for_manual_install = package.replace('[pil]', ' qrcode[pil]')
        print(f"[!] Please check your pip installation and install manually: pip install {package_name_for_manual_install}")
        sys.exit(1)
    except FileNotFoundError:
        print("[!] Error: 'pip' command not found. Make sure Python and pip are installed correctly and in your system's PATH.")
        sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] 'requests' library not found.")
    install_package("requests")
    try:
        import requests # Try importing again
    except ImportError:
        print("[!] Failed to import 'requests' after attempting installation. Please install it manually.")
        sys.exit(1)


try:
    import qrcode
    from PIL import Image # Needed for qrcode[pil]
except ImportError:
    print("[!] 'qrcode' or 'Pillow' library not found.")
    install_package("qrcode[pil]") # Install with Pillow support
    try:
        import qrcode
        from PIL import Image # Try importing again
    except ImportError:
        print("[!] Failed to import 'qrcode' or 'PIL' after attempting installation. Please install 'qrcode[pil]' manually.")
        sys.exit(1)
# --- End of Dependency Installation ---


# --- Original Script Code Starts (with minor modifications for QR) ---

referral = "LUMyNTc5ZjItZGYyNy00ZGFhLWI5ZDgtN2E3MDk4MzdkZjYy" # change it with yours referral ID
baseURL = "https://api.cloudflareclient.com/v0a745"
path = "/reg"
url = baseURL + path
install_id = ""
private_key = ""
device_token = ""
fcm_token = ""
tos = ""
warp_enabled = ""
status_code = ""
license_key = ""

# Function to generate random string for device name
def genString(stringLength):
    try:
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(stringLength))
    except Exception as error:
        print("Error generating random string:", error)

# Function to generate WARP+ license key (Not used directly in scanner but part of original code)
def gen_license_key():
    try:
        letters = string.ascii_uppercase + string.digits
        part1 = ''.join(random.choice(letters) for i in range(8))
        part2 = ''.join(random.choice(letters) for i in range(8))
        part3 = ''.join(random.choice(letters) for i in range(8))
        return f"{part1}-{part2}-{part3}"
    except Exception as error:
        print("Error generating license key:", error)
        return None

# Function to register WARP account
def register_warp_account():
    global install_id, private_key, device_token, fcm_token, tos, warp_enabled, status_code, license_key
    try:
        install_id = genString(22)
        data = {"key": "{}=".format(genString(43)),
                "install_id": install_id,
                "fcm_token": "{}:APA91b{}".format(install_id, genString(134)),
                "referrer": referral,
                "warp_enabled": False,
                "tos": datetime.datetime.now().isoformat()[:-3] + "+02:00", # Using local timezone might be better
                "type": "Android",
                "locale": "en_US"} # Changed locale to en_US
        headers = {'Content-Type': 'application/json; charset=UTF-8',
                   'Host': 'api.cloudflareclient.com',
                   'Connection': 'Keep-Alive',
                   'Accept-Encoding': 'gzip',
                   'User-Agent': 'okhttp/3.12.1'
                   }
        print("[*] Registering WARP account...")
        response = requests.post(url, data=json.dumps(data), headers=headers)
        status_code = response.status_code
        if status_code == 200:
            response_data = response.json()
            private_key = response_data["config"]["private_key"]
            # Ensure peer_public_key exists before accessing
            peer_public_key = response_data["config"]["peers"][0]["public_key"] if response_data["config"].get("peers") else "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" # Default fallback
            # Ensure interface addresses exist
            interface_addresses = response_data["config"]["interface"].get("addresses", {})
            v4_address = interface_addresses.get("v4", "172.16.0.2/32") # Default fallback
            v6_address = interface_addresses.get("v6", "2606:4700:110: beteiligt:1a29:5f9a/128") # Default fallback

            device_token = response_data["token"]
            fcm_token = data["fcm_token"]
            tos = data["tos"]
            warp_enabled = data["warp_enabled"]
            license_key = response_data["account"]["license"]
            print("[+] WARP Account Registered Successfully!")
            # Optional: Store details needed for config generation globally or return them
            global account_config_details
            account_config_details = {
                "private_key": private_key,
                "peer_public_key": peer_public_key,
                "v4_address": v4_address,
                "v6_address": v6_address
            }
            return True
        else:
            print(f"[!] Error registering WARP account. Status Code: {status_code}")
            print(f"[!] Response: {response.text}")
            return False
    except Exception as error:
        print("[!] Error registering WARP account:", error)
        return False

# Function to check WARP+ status using license key
def check_warp_plus_status(license_key_to_check=None): # Use account's key if none provided
    global device_token
    if not device_token:
        print("[!] Cannot check status: Device token not available (registration failed?).")
        return False
    try:
        headers = {"Authorization": f"Bearer {device_token}",
                   'Content-Type': 'application/json; charset=UTF-8',
                   'Host': 'api.cloudflareclient.com',
                   'Connection': 'Keep-Alive',
                   'Accept-Encoding': 'gzip',
                   'User-Agent': 'okhttp/3.12.1'}
        get_account_url = f"{baseURL}/reg/{device_token}/account"
        response = requests.get(get_account_url, headers=headers)
        if response.status_code == 200:
            account_data = response.json()
            if account_data.get("account_type") == "limited":
                print("[+] WARP+ Status: Activated (Limited)")
                return True
            elif account_data.get("referral_count", 0) > 0:
                print(f"[+] WARP+ Status: Activated ({account_data.get('referral_count')} GB)")
                return True
            else:
                print("[-] WARP+ Status: Not Activated")
                return False
        else:
            print(f"[!] Error checking WARP+ status. Status Code: {response.status_code}")
            print(f"[!] Response: {response.text}")
            return False
    except Exception as error:
        print("[!] Error checking WARP+ status:", error)
        return False

# Function to apply WARP+ license key
def apply_warp_plus_license(license_key_to_apply):
    global device_token
    if not device_token:
        print("[!] Cannot apply key: Device token not available (registration failed?).")
        return False
    try:
        headers = {"Authorization": f"Bearer {device_token}",
                   'Content-Type': 'application/json; charset=UTF-8',
                   'Host': 'api.cloudflareclient.com',
                   'Connection': 'Keep-Alive',
                   'Accept-Encoding': 'gzip',
                   'User-Agent': 'okhttp/3.12.1'}
        patch_account_url = f"{baseURL}/reg/{device_token}/account"
        data = {"license": license_key_to_apply}
        response = requests.patch(patch_account_url, data=json.dumps(data), headers=headers)
        if response.status_code == 200:
            account_data = response.json()
            if account_data.get("account_type") == "limited" or account_data.get("referral_count", 0) > 0:
                print(f"[+] Successfully applied WARP+ License Key: {license_key_to_apply}")
                return True
            else:
                 print(f"[-] Failed to apply WARP+ License Key: {license_key_to_apply}. Account type: {account_data.get('account_type')}")
                 return False
        elif response.status_code == 400: # Often indicates invalid key
             print(f"[-] Failed to apply WARP+ License Key (Invalid Key?): {license_key_to_apply}")
             return False
        else:
            print(f"[!] Error applying WARP+ license key. Status Code: {response.status_code}")
            print(f"[!] Response: {response.text}")
            return False
    except Exception as error:
        print("[!] Error applying WARP+ license key:", error)
        return False

# Function to generate WireGuard config file content using details from registration
def generate_config_content(ip, port):
    global account_config_details
    if not account_config_details:
         print("[!] Cannot generate config: Account details not available.")
         # Provide default values or handle error appropriately
         acc_private_key = "PRIVATE_KEY_HERE" # Placeholder
         acc_v4 = "172.16.0.2/32"
         acc_v6 = "2606:4700:110:beteiligt:1a29:5f9a/128" # Placeholder v6, original had typo
         peer_pub_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" # Default public key
    else:
         acc_private_key = account_config_details['private_key']
         acc_v4 = account_config_details['v4_address']
         acc_v6 = account_config_details['v6_address']
         peer_pub_key = account_config_details['peer_public_key']

    content = f"""
[Interface]
PrivateKey = {acc_private_key}
Address = {acc_v4}, {acc_v6}
DNS = 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 2606:4700:4700::1111, 2606:4700:4700::1001, 2001:4860:4860::8888, 2001:4860:4860::8844
MTU = 1280

[Peer]
PublicKey = {peer_pub_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {ip}:{port}
"""
    return content.strip() # Use strip() to remove leading/trailing whitespace

# --- Function to generate and save/show QR code ---
def generate_qr_code(config_content, filename_base):
    """Generates a QR code from the config content."""
    try:
        qr = qrcode.QRCode(
            version=1, # Auto version might be better: qr = qrcode.QRCode(box_size=10, border=4)
            error_correction=qrcode.constants.ERROR_CORRECT_L, # L = Low, M = Medium, Q = Quartile, H = High
            box_size=10, # Size of each box in pixels
            border=4, # Thickness of the border (number of boxes)
        )
        qr.add_data(config_content)
        qr.make(fit=True) # Fit the data to the QR code dimensions

        img = qr.make_image(fill_color="black", back_color="white")

        # Option 1: Save QR code to a file
        qr_filename = f"{filename_base}.png"
        img.save(qr_filename)
        print(f"[+] QR Code saved to: {qr_filename}")

        # Option 2: Display QR code (might not work in all terminals/environments)
        # Uncomment the following line if you have a compatible terminal/viewer
        # try:
        #     img.show()
        #     print("[+] QR Code displayed (if terminal/viewer supported).")
        # except Exception as display_error:
        #      print(f"[!] Could not display QR code automatically: {display_error}")

    except Exception as e:
        print(f"[!] Error generating QR Code: {e}")
# --- End of QR Code Function ---

# Function to check IP using Cloudflare trace via SOCKS5 proxy
def check_ip(proxy_ip, proxy_port, timeout=5):
    proxy = {'http': f'socks5h://{proxy_ip}:{proxy_port}', 'https': f'socks5h://{proxy_ip}:{proxy_port}'}
    try:
        # print(f"[*] Checking IP: {proxy_ip}:{proxy_port}...") # Debug print
        response = requests.get("https://www.cloudflare.com/cdn-cgi/trace", proxies=proxy, timeout=timeout)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        trace_data_str = response.text.strip()
        trace_data = dict(line.split('=') for line in trace_data_str.split('\n') if '=' in line)

        # print(f"Trace for {proxy_ip}:{proxy_port} -> {trace_data}") # Debug print

        if trace_data.get('warp') == 'on' or trace_data.get('warp') == 'plus':
            location = trace_data.get('loc', 'N/A') # Default to N/A if loc is missing
            ip_address = trace_data.get('ip', 'N/A') # Default to N/A if ip is missing
            print(f"[+] GOOD Result Found! IP: {proxy_ip}:{proxy_port}, Location: {location}, Trace IP: {ip_address}")
            return True, ip_address # Return True and the IP address from trace
        else:
            # print(f"[-] Bad Result or Warp Off for: {proxy_ip}:{proxy_port}") # Debug print
            return False, None
    except requests.exceptions.Timeout:
        # print(f"[!] Timeout for: {proxy_ip}:{proxy_port}") # Debug print
        return False, None
    except requests.exceptions.ProxyError:
         # print(f"[!] Proxy Error for: {proxy_ip}:{proxy_port} (Connection refused or invalid proxy type?)") # Debug print
         return False, None
    except requests.exceptions.RequestException as e:
        # print(f"[!] Request Error for {proxy_ip}:{proxy_port}: {e}") # Debug print
        return False, None
    except Exception as e:
        # print(f"[!] Unknown Error for {proxy_ip}:{proxy_port}: {e}") # Debug print
        return False, None


# --- Main Scanner Logic ---
def scanner(ip, port, wg_config_dir="wg-configs"):
    result, trace_ip = check_ip(ip, port) # Get result and IP from check_ip
    if result:
        # Create directory if it doesn't exist
        if not os.path.exists(wg_config_dir):
            try:
                os.makedirs(wg_config_dir)
                print(f"[*] Directory '{wg_config_dir}' created.")
            except OSError as e:
                print(f"[!] Error creating directory '{wg_config_dir}': {e}")
                return None # Exit if directory creation fails

        # Generate config content using account details
        config_content = generate_config_content(ip, port)
        if not config_content: # Check if config generation failed
             return None

        # Save config file
        # Replace invalid filename characters if needed (though IPs/ports are usually fine)
        safe_ip = ip.replace('.', '_')
        filename_base = os.path.join(wg_config_dir, f"warp_{safe_ip}_{port}") # Use os.path.join for cross-platform compatibility
        config_filename = f"{filename_base}.conf"
        try:
            with open(config_filename, "w") as f:
                f.write(config_content)
            print(f"[+] Config saved to: {config_filename}")

            # --- Generate QR Code for the saved config ---
            generate_qr_code(config_content, filename_base)
            # --- End of QR Code Generation Call ---

        except IOError as e:
            print(f"[!] Error saving config file '{config_filename}': {e}")
            return None # Indicate failure

        return ip, port # Return successful IP and port
    return None # Return None if check failed


# --- Main Execution ---
if __name__ == "__main__":
    # Register WARP account first (essential for getting keys)
    account_config_details = None # Initialize global dict
    if not register_warp_account():
        print("[!] WARP account registration failed. Exiting.")
        sys.exit(1)

    # Optional: Apply WARP+ key
    apply_key_choice = input("[?] Do you want to apply a WARP+ license key? (y/n, default n): ").lower().strip()
    if apply_key_choice == 'y':
        user_license_key = input("[*] Please enter your WARP+ license key: ").strip()
        if user_license_key:
            print("[*] Applying license key...")
            apply_warp_plus_license(user_license_key)
            # Check status after applying
            print("[*] Checking WARP+ status after applying key...")
            time.sleep(1) # Brief pause before checking
            check_warp_plus_status() # Check status of the account's current key
        else:
            print("[-] No license key entered. Continuing without applying.")

    # --- Get IPs and Ports ---
    print("[*] Fetching IP list...")
    try:
        # Using a reliable source for Cloudflare IPs
        response = requests.get('https://raw.githubusercontent.com/ircfspace/scanner/main/ipv4.list', timeout=10)
        # Alternative source: response = requests.get('https://raw.githubusercontent.com/NiREvil/vless/main/ipv4.txt', timeout=10)
        response.raise_for_status()
        ips = response.text.strip().split('\n')
        # Filter out potential empty lines or comments if necessary
        ips = [ip.strip() for ip in ips if ip.strip() and not ip.startswith('#')]
        print(f"[*] Fetched {len(ips)} IPs.")
    except requests.RequestException as e:
        print(f"[!] Error fetching IP list: {e}")
        # Fallback IPs if download fails
        ips = ["162.159.192.1", "162.159.192.10", "162.159.193.1", "162.159.193.10", "162.159.195.1", "162.159.195.10",
               "188.114.96.1", "188.114.96.10", "188.114.97.1", "188.114.97.10", "188.114.98.1", "188.114.98.10", "188.114.99.1", "188.114.99.10"]
        print(f"[*] Using default fallback IP list: {len(ips)} IPs")
    except Exception as e:
        print(f"[!] Unknown error processing IPs: {e}")
        sys.exit(1)

    # Common WARP ports (ensure they are integers)
    ports_str = ["4500", "8854", "9007", "908", "2408", "500", "854", "8854", "1701", "754", "9080", "8086", "80"] # Added port 80
    ports = [int(p) for p in ports_str]


    # --- Scan IPs ---
    print("[*] Starting IP scan...")
    good_results = []
    max_workers = 100 # Adjust number of threads based on your system and network
    start_time = time.time()

    # Directory for saving configs
    config_directory = "wg-configs"

    # Using ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a list of tasks (futures)
        futures = [executor.submit(scanner, ip, port, config_directory) for ip in ips for port in ports]

        # Process completed tasks as they finish
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    good_results.append(result)
                    print(f"[*] Good results found so far: {len(good_results)}")
                    # Optional: Stop after finding a certain number of good results
                    # if len(good_results) >= 10: # Example: Stop after 10 results
                    #    print("[*] Sufficient number of good results found. Stopping scan...")
                    #    # Attempt to cancel pending futures (might not work for already running tasks)
                    #    for f in futures:
                    #        if not f.done():
                    #            f.cancel()
                    #    executor.shutdown(wait=False) # Don't wait for running tasks to finish
                    #    break # Exit the loop processing completed futures
            except Exception as exc:
                 # Log errors from individual threads if needed
                 # This helps diagnose issues within the scanner function itself
                 print(f"[!] An error occurred in a scanning thread: {exc}")


    end_time = time.time()
    duration = end_time - start_time
    print(f"\n[*] Scan completed in {duration:.2f} seconds.")
    print(f"[*] Total good results found: {len(good_results)}")

    if not good_results:
        print("[!] No working WARP IP:Port combinations found.")

    # Optional: Print summary of good results at the end
    # if good_results:
    #    print("\n--- Summary of Good Results ---")
    #    for ip, port in good_results:
    #        print(f"  IP: {ip}, Port: {port}")
    #    print(f"  Configs and QR Codes saved in '{config_directory}' directory.")
    #    print("-----------------------------")

