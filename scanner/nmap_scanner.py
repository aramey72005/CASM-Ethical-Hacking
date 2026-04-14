import subprocess
import os

def run_scan(target="127.0.0.1"):
    os.makedirs("scan_results", exist_ok=True)

    output_file = "scan_results/scan.xml"

    cmd = [
        "nmap",
        "-sV",
        "-oX",
        output_file,
        target
    ]

    subprocess.run(cmd, capture_output=True, text=True)

    return output_file