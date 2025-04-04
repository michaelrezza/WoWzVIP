V = 71
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
    print("Retrying module not installed. Installing now...")
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

# --- Adding qrcode import ---
try:
    import qrcode
except ImportError:
    print("qrcode module not installed. Installing now...")
    os.system('pip install qrcode[pil]')
    import qrcode

api = ''
ports = [1074, 894, 908, 878]
console = Console()
wire_config_temp = ''
wire_c = 1
wire_p = 0
send_msg_wait = 0
results = []
resultss = []
save_result = []
save_best = []
best_result = []
WoW_v2 = ''
isIran = ''
max_workers_number = 0
do_you_save = '2'
which = ''
ping_range = 'n'

def gt_resolution():
    return os.get_terminal_size().columns

# --- Adding a new function for generating QR code ---
def generate_v2ray_qr(config_data, output_file="v2ray_qr.png"):
    """
    Generates a QR code for the provided v2ray configuration data and saves it to the specified file.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(config_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_file)
    console.print(f"[green]QR code saved to: {output_file}[/green]")

# --- Main Execution Block ---
if __name__ == "__main__":
    import sys
    # Checking --qrcode argument for QR code generation
    if len(sys.argv) > 1 and sys.argv[1] == "--qrcode":
        from rich.prompt import Prompt
        config = Prompt.ask("Please enter your v2ray configuration or link")
        generate_v2ray_qr(config)
        sys.exit(0)

    os.system('clear')
    what = start_menu()
    
    if what == '1':
        do_you_save = input_p('Do you want to save in a result CSV?\n', {"1": 'Yes', "2": "No"})
        which = 'n'
        if do_you_save == '1':
            os.system('termux-setup-storage')
            which = input_p('Do you want to save for bpb panel (comma-separated) or vahid panel (newline-separated) in the CSV?\n', {
                '1': 'bpb panel (comma-separated)',
                '2': 'vahid panel (newline-separated)',
                '3': 'with score',
                '4': 'clean'
            })
            if which != "4":
                need_port = input_p('Do you want to save the port in the result?\n', {'1': 'Yes', '2': 'No'})

            if which == '4':
                which = input_p('Do you want for bpb panel (comma-separated) or vahid panel (newline-separated)?\n', {
                    '1': 'bpb panel (comma-separated)',
                    '2': 'vahid panel (newline-separated)'
                })
                with open('/storage/emulated/0/result.csv', 'r') as f:
                    b = f.readlines()
                    with open('/storage/emulated/0/clean_result.csv', 'w') as ff:
                        for j in b:
                            if which == '1':
                                ff.write(j[:j.index('|') - 1])
                                if j != b[len(b) - 1]:
                                    ff.write(',')
                            else:
                                ff.write(j[:j.index('|') - 1])
                                ff.write('\n')
                print('Saved in /storage/emulated/0/clean_result.csv!')
                exit()
        main()
    elif what in ['2', '3', '7', '13', '15', '16']:
        if what in ['7', '13']:
            polrn_block = input_p('Do you want to block adult sites?\n', {"1": "Yes", "2": "No"})
            isIran = input_p('Choose server location\n', {"1": "Iran (Faster Speed)", "2": "Germany (Slower Speed)"})
        main2()
    elif what in ['4', '17']:
        how_many = get_number_of_configs()
        for i in range(how_many):
            main3()
    elif what in ['5', '6', '11', '12']:
        api_url = 'http://s9.serv00.com:1074/arshiacomplus/api/wirekey'
        rprint("[bold green]Please wait, generating WireGuard URL...[/bold green]")
        try:
            config = fetch_config_from_api()
        except Exception as e:
            print('Try again. Error =', e)
            exit()
        wireguard_url = generate_wireguard_url(config)
        if wireguard_url:
            os.system('clear')
            print(f"\n\n{wireguard_url}\n\n")
        else:
            print("Failed to generate WireGuard URL.")
    elif what == '00':
        info()
    elif what == '0':
        gojo_goodbye_animation()
        time.sleep(1)
        console.print("\n[bold magenta]Exiting... Goodbye![/bold magenta]")
        exit()
