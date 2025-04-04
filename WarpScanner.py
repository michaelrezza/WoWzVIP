# -*- coding: utf-8 -*-
import subprocess
import sys
import os
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import csv
import socket
import ipaddress

# --- Dependency Installation Function ---
def install_dependencies():
    """Checks and installs required libraries."""
    required_packages = ['requests', 'rich', 'qrcode[pil]']
    missing_packages = []

    for package in required_packages:
        package_name = package.split('[')[0] # Get base package name (e.g., qrcode from qrcode[pil])
        try:
            # Check if Pillow is installed specifically for qrcode[pil]
            if package_name == 'qrcode':
                __import__('PIL')
            __import__(package_name)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"Installing required libraries: {', '.join(missing_packages)}...")
        try:
            # Ensure pip is available and use it correctly
            pip_executable = sys.executable.replace('python.exe', 'pip.exe') if platform.system() == "Windows" else "pip" # Basic check, might need refinement
            if not os.path.exists(pip_executable) and platform.system() != "Windows":
                 pip_executable = "pip3" # Try pip3 on non-windows

            # Check if pip exists before trying to use it
            try:
                 subprocess.check_call([pip_executable, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (FileNotFoundError, subprocess.CalledProcessError):
                 # If pip/pip3 not found directly, try python -m pip
                 pip_command = [sys.executable, "-m", "pip"]
                 try:
                     subprocess.check_call(pip_command + ["--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 except (FileNotFoundError, subprocess.CalledProcessError):
                     print("Error: pip command not found. Please ensure pip is installed and in your PATH.")
                     sys.exit(1)
            else:
                 pip_command = [pip_executable] # Use found pip/pip3

            # Proceed with installation
            subprocess.check_call(pip_command + ["install"] + missing_packages)

            print("Installation successful.")
            # Re-import after installation
            print("Reloading script to import new libraries...")
            os.execv(sys.executable, [sys.executable] + sys.argv) # Restart script to load new modules
        except Exception as e:
            print(f"Error installing dependencies: {e}")
            print("Please install manually: pip install requests rich 'qrcode[pil]'")
            sys.exit(1)
    else:
        print("All prerequisites are installed.")

# --- Run Dependency Installation ---
install_dependencies()

# --- Import Libraries After Check/Install ---
try:
    import requests
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    import qrcode
    from PIL import Image # Pillow is needed for qrcode[pil]
except ImportError:
    print("Error importing libraries after installation. Please restart the script.")
    sys.exit(1)


# --- Initial Settings ---
console = Console()
TIMEOUT_SECONDS = 1  # Timeout for each IP test request
CONCURRENT_WORKERS = 100 # Number of concurrent tests
RESULT_FILE = "result.csv"
QR_CODE_FOLDER = "warp_qr_codes"

# Create the folder for QR codes if it doesn't exist
if not os.path.exists(QR_CODE_FOLDER):
    os.makedirs(QR_CODE_FOLDER)

# --- Helper Functions ---

def clear_screen():
    """Clears the terminal screen."""
    command = 'cls' if platform.system().lower() == "windows" else 'clear'
    os.system(command)

def generate_vless_config(ip_address, port=443):
    """Generates a VLESS config link for the given IP."""
    # Default VLESS parameters for WARP
    uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff" # Example UUID - better to generate a real one
    sni = "sni.cloudflare.com" # Or another valid Cloudflare SNI
    ws_path = "/?ed=2048"
    host = "www.cloudflare.com" # Or SNI
    config_name = f"WARP-{ip_address}"

    # Build VLESS link
    vless_link = f"vless://{uuid}@{ip_address}:{port}?encryption=none&security=tls&sni={sni}&fp=randomized&type=ws&host={host}&path={ws_path}#{config_name}"
    return vless_link

def generate_qr_code(text, filename):
    """Generates and displays QR Code in terminal and saves to file."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)

        # Display in terminal
        console.print("\n[bold green]QR Code (may appear small in some terminals):[/bold green]")
        qr.print_tty()

        # Save to file
        img = qr.make_image(fill_color="black", back_color="white")
        filepath = os.path.join(QR_CODE_FOLDER, filename)
        img.save(filepath)
        console.print(f"[cyan]QR Code successfully saved to file:[/cyan] [bold]{filepath}[/bold]")

    except Exception as e:
        console.print(f"[bold red]Error generating QR Code:[/bold red] {e}")

def check_ip(ip, progress, task_id, successful_ips, checked_count, total_count):
    """Tests connection to an IP and measures latency."""
    ports = [443, 8443, 2053, 2096, 2087, 2083] # Common WARP ports
    url_template = "https://{ip}:{port}/cdn-cgi/trace"
    headers = {'User-Agent': 'Mozilla/5.0'}
    latency = float('inf')
    is_successful = False
    selected_port = None # Store the successful port

    for port in ports:
        try:
            url = url_template.format(ip=ip, port=port)
            start_time = time.time()
            # Use socket for a faster check if the port is open before the HTTP request
            with socket.create_connection((ip, port), timeout=TIMEOUT_SECONDS / 2):
                 # Port is open, now try HTTP GET
                 # Disable SSL verification for Cloudflare IPs
                 response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS / 2, verify=False)
                 response.raise_for_status() # Check for HTTP errors
                 # Check for WARP indicators or HTTPS scheme
                 if 'warp=on' in response.text or 'visit_scheme=https' in response.text:
                     end_time = time.time()
                     current_latency = (end_time - start_time) * 1000 # Convert to milliseconds
                     # Select the port with the lowest latency
                     if current_latency < latency:
                          latency = current_latency
                          selected_port = port # Update the best port found
                     is_successful = True
                     # break # Uncomment if you want to stop after the first successful port

        except (requests.exceptions.RequestException, socket.timeout, socket.error, OSError):
            continue # Move to the next port or finish test for this IP
        except Exception: # Catch other unexpected errors
            continue

    # Update progress bar
    checked_count[0] += 1
    progress.update(task_id, advance=1, description=f"[cyan]Checked: {checked_count[0]}/{total_count}")

    if is_successful and selected_port is not None:
        successful_ips.append({'ip': ip, 'latency': f"{latency:.2f} ms", 'port': selected_port})
        console.print(f"[green] Healthy IP Found: {ip}:{selected_port} | Latency: {latency:.2f} ms [/green]")

        # --- Generate Config and QR Code ---
        vless_config = generate_vless_config(ip, selected_port) # Use the found working port
        console.print(f"[blue]VLESS Config:[/blue] [bold yellow]{vless_config}[/bold yellow]")
        generate_qr_code(vless_config, f"warp_vless_{ip}_{selected_port}.png") # Include port in filename
        console.print("-" * 30) # Separator

        # Save the healthy IP to the CSV file
        with open(RESULT_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write IP, Latency, and Port
            writer.writerow([ip, f"{latency:.2f}", selected_port])

        return True
    return False


def get_cf_ranges(url="https://www.cloudflare.com/ips-v4"):
    """Fetches Cloudflare IP ranges."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error fetching Cloudflare IP ranges:[/bold red] {e}")
        return []

def get_country_cf_ranges(country_code):
    """Fetches Cloudflare IP ranges for a specific country."""
    # This is a simplified example, requires a reliable data source for country-specific IPs
    # You could use services like ipinfo.io or GeoIP databases
    # Currently returns public ranges as an example
    console.print(f"[yellow]Note: Fetching country-specific ({country_code}) IPs is currently using the general list in this version.[/yellow]")
    return get_cf_ranges() # Returns the same general list in this simple implementation

def ips_from_ranges(ranges):
    """Generates IPs from a list of CIDR ranges."""
    ips = []
    console.print("[cyan]Generating IPs from CIDR ranges...[/cyan]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True # Hide progress bar when done
    ) as progress:
        task_id = progress.add_task("[cyan]Processing ranges...", total=len(ranges))
        processed_count = 0
        for cidr in ranges:
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                # To avoid generating too many IPs, maybe sample or limit
                # count = 0
                for ip in net:
                     ips.append(str(ip))
                     # count += 1
                     # if count >= 10: # Limit IPs per range (optional)
                     #   break
            except ValueError:
                # console.print(f"[yellow]Invalid range ignored: {cidr}[/yellow]") # Can be noisy
                pass
            except Exception as e:
                console.print(f"[red]Error processing range {cidr}: {e}[/red]")
            processed_count += 1
            progress.update(task_id, advance=1, description=f"[cyan]Processed {processed_count}/{len(ranges)} ranges")
    console.print(f"[green]Generated {len(ips)} IPs from {len(ranges)} ranges.[/green]")
    return ips


def scan_ips(ip_list):
    """Scans a list of IPs concurrently."""
    successful_ips = []
    checked_count = [0] # Use list for mutable integer access within threads
    total_count = len(ip_list)

    # Create result file if it doesn't exist and write header
    if not os.path.exists(RESULT_FILE) or os.path.getsize(RESULT_FILE) == 0:
        with open(RESULT_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Add Port to header
            writer.writerow(['IP Address', 'Latency (ms)', 'Port'])

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        # transient=True # Keep progress visible after completion to show final stats
    ) as progress:
        task_id = progress.add_task("[cyan]Starting scan...", total=total_count)
        futures = {}
        with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
             futures = {executor.submit(check_ip, ip, progress, task_id, successful_ips, checked_count, total_count): ip for ip in ip_list}

             # Wait for tasks to complete (progress is updated within check_ip)
             for future in as_completed(futures):
                  try:
                      future.result() # Retrieve result to catch potential exceptions from the thread
                  except Exception as exc:
                      failed_ip = futures[future]
                      # Log errors if needed, but can be very verbose
                      # console.print(f"[yellow]Error processing IP {failed_ip}: {exc}[/yellow]", highlight=False)


    console.print(f"\n[bold green]Scan complete. {len(successful_ips)} healthy IPs found and saved to {RESULT_FILE}.[/bold green]")
    console.print(f"[bold cyan]QR Codes saved in folder: {QR_CODE_FOLDER}[/bold cyan]")

    # Display results in a table (optional)
    if successful_ips:
        # Sort results by latency (numerically)
        successful_ips.sort(key=lambda x: float(x['latency'].split()[0]))

        table = Table(title="Scan Results - Healthy WARP IPs")
        table.add_column("No.", style="dim", width=6)
        table.add_column("IP Address", style="magenta")
        table.add_column("Port", style="blue") # Add port column
        table.add_column("Latency (ms)", style="cyan")


        for i, data in enumerate(successful_ips):
             # Add port to the table row
             table.add_row(str(i+1), data['ip'], str(data['port']), data['latency'])
        console.print(table)
    else:
        console.print("[yellow]No healthy IPs were found.[/yellow]")


# --- Main Menu ---
def display_menu():
    """Displays the main menu."""
    clear_screen()
    console.print(Panel(
        "[bold yellow]WARP IP Scanner & V2Ray QR Generator[/bold yellow]\n"
        "[cyan]Script originally by Arshia, modified by Gemini[/cyan]\n"
        f"[green]Results file:[/green] {RESULT_FILE}\n"
        f"[green]QR Code folder:[/green] {QR_CODE_FOLDER}",
        title="[bold blue]Main Menu[/bold blue]",
        border_style="blue"
    ))
    print("\nOptions:")
    print("  [1] Scan IPs from ip.txt file (one IP per line)")
    print("  [2] Scan an IP range (e.g., 192.168.1.1-192.168.1.255)")
    print("  [3] Scan all public Cloudflare IP ranges")
    print("  [4] Scan Cloudflare IP ranges for a specific country (e.g., IR, DE)")
    # The original options 5-8 correspond to 1-4 here.
    # Original options 11-14 likely require other scripts or more complex logic
    # and are not directly related to IP scanning, so they haven't been merged here.
    print("  [0] Exit")

# --- Main Program Loop ---
if __name__ == "__main__":
    # Disable InsecureRequestWarning messages
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    while True:
        display_menu()
        choice = input("\nEnter your choice: ").strip()

        ips_to_scan = []

        if choice == '1':
            try:
                # Default to ip.txt if exists, else prompt
                ip_file = 'ip.txt'
                if not os.path.exists(ip_file):
                     ip_file = input("Enter the path to the IP file (default ip.txt): ").strip() or 'ip.txt'

                with open(ip_file, 'r') as f:
                    # Basic IP validation
                    ips_to_scan = [line.strip() for line in f if line.strip() and '.' in line] # Simple check
                if not ips_to_scan:
                    console.print(f"[yellow]File '{ip_file}' is empty or contains no valid IPs.[/yellow]")
                    time.sleep(2)
                    continue
                console.print(f"[cyan]Starting scan for IPs from file '{ip_file}' ({len(ips_to_scan)} IPs)...[/cyan]")
            except FileNotFoundError:
                console.print(f"[bold red]Error: File '{ip_file}' not found.[/bold red]")
                time.sleep(2)
                continue
            except Exception as e:
                 console.print(f"[bold red]Error reading file '{ip_file}': {e}[/bold red]")
                 time.sleep(2)
                 continue


        elif choice == '2':
            ip_range_str = input("Enter IP range (e.g., 192.168.1.1-192.168.1.100): ").strip()
            try:
                if '-' not in ip_range_str:
                     raise ValueError("Invalid range format. Use StartIP-EndIP")
                start_ip_str, end_ip_str = ip_range_str.split('-')
                start_ip = ipaddress.ip_address(start_ip_str.strip())
                end_ip = ipaddress.ip_address(end_ip_str.strip())

                if start_ip.version != end_ip.version:
                     raise ValueError("Start and End IP versions must match.")
                if start_ip > end_ip:
                     raise ValueError("Start IP must be less than or equal to End IP.")

                current_ip = start_ip
                while current_ip <= end_ip:
                    ips_to_scan.append(str(current_ip))
                    # Handle potential overflow for IPv6 if needed, though unlikely for manual ranges
                    if current_ip == end_ip: break
                    current_ip += 1

                if not ips_to_scan:
                    console.print("[yellow]The entered IP range is invalid or empty.[/yellow]")
                    time.sleep(2)
                    continue
                console.print(f"[cyan]Starting scan for IP range {ip_range_str} ({len(ips_to_scan)} IPs)...[/cyan]")
            except ValueError as e:
                console.print(f"[bold red]Error processing IP range:[/bold red] {e}")
                time.sleep(2)
                continue
            except Exception as e:
                 console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
                 time.sleep(2)
                 continue

        elif choice == '3':
            console.print("[cyan]Fetching public Cloudflare IP ranges...[/cyan]")
            cf_ranges = get_cf_ranges()
            if not cf_ranges:
                console.print("[bold red]Error: Failed to fetch Cloudflare ranges.[/bold red]")
                time.sleep(2)
                continue
            # console.print("[cyan]Generating IP list from ranges (may take time)...[/cyan]") # Moved inside ips_from_ranges
            ips_to_scan = ips_from_ranges(cf_ranges)
            if not ips_to_scan:
                console.print("[yellow]No valid IPs generated from Cloudflare ranges.[/yellow]")
                time.sleep(2)
                continue
            # Warning for potentially huge number of IPs
            console.print(f"[yellow]Warning: The number of IPs to scan ({len(ips_to_scan)}) is very large. This operation may take a very long time.[/yellow]")
            confirm = input("Do you want to continue? (y/n): ").lower()
            if confirm != 'y':
                continue
            console.print("[cyan]Starting scan for public Cloudflare IPs...[/cyan]")


        elif choice == '4':
             country = input("Enter the 2-letter country code (e.g., US, DE, IR): ").upper()
             console.print(f"[cyan]Fetching Cloudflare IP ranges for country {country}...[/cyan]")
             # Note: This section needs improvement and currently uses the public list.
             country_ranges = get_country_cf_ranges(country)
             if not country_ranges:
                 console.print(f"[bold red]Error: Failed to fetch Cloudflare ranges for {country}.[/bold red]")
                 time.sleep(2)
                 continue
             # console.print("[cyan]Generating IP list from ranges...[/cyan]") # Moved inside ips_from_ranges
             ips_to_scan = ips_from_ranges(country_ranges)
             if not ips_to_scan:
                 console.print(f"[yellow]No valid IPs generated for {country}.[/yellow]")
                 time.sleep(2)
                 continue
             console.print(f"[cyan]Starting scan for Cloudflare IPs for country {country} ({len(ips_to_scan)} IPs)...[/cyan]")

        elif choice == '0':
            console.print("[bold blue]Exiting program...[/bold blue]")
            break

        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            time.sleep(2)
            continue

        # Execute scan if a list of IPs has been prepared
        if ips_to_scan:
            random.shuffle(ips_to_scan) # Shuffle for better load distribution
            scan_ips(ips_to_scan)
            input("\nPress Enter to return to the main menu...") # Wait for user to see results

