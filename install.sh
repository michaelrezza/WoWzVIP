#!/bin/bash

# Update packages and install required dependencies
echo "Updating packages and installing required dependencies..."
pkg update -y || { echo "Failed to update packages. Exiting."; exit 1; }
pkg install -y python python-pip git curl wget || { echo "Failed to install required packages. Exiting."; exit 1; }

# Install required Python modules
echo "Installing required Python modules..."
pip install --upgrade pip
pip install requests qrcode[pil] rich retrying icmplib alive_progress cryptography || { echo "Failed to install Python modules. Exiting."; exit 1; }

# Download and modify WarpScanner.py to add QR Code functionality
echo "Downloading and modifying WarpScanner.py..."
curl -fsSL -o WarpScanner.py https://raw.githubusercontent.com/arshiacomplus/WarpScanner/main/WarpScanner.py || { echo "Failed to download WarpScanner.py. Exiting."; exit 1; }

# Add QR Code generation capability to WarpScanner.py
cat <<EOF >> WarpScanner.py

# --- QR Code Generator for v2ray ---
try:
    import qrcode
except ImportError:
    print("qrcode module not installed. Installing now...")
    os.system('pip install qrcode[pil]')
    import qrcode

def generate_v2ray_qr(config_text):
    try:
        img = qrcode.make(config_text)
        img.save("v2ray_qr.png")
        print("[QR Code generated: 'v2ray_qr.png']")
    except Exception as e:
        print(f"Failed to generate QR Code: {e}")

if __name__ == '__main__':
    from rich.prompt import Prompt
    answer = Prompt.ask("Do you want to generate QR Code for v2ray config?", choices=["y", "n"], default="n")
    if answer.lower() == "y":
        config = fetch_config_from_api()
        config_str = json.dumps(config, indent=4)
        generate_v2ray_qr(config_str)
EOF

# Run the main script
echo "Starting WarpScanner..."
python WarpScanner.py
