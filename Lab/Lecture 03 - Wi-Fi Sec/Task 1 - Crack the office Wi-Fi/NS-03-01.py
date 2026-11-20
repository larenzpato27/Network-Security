import subprocess
import shutil
import re

PCAP_FILE = "capture-6.pcap"
SSID = "Acme-WiFi"
PASSWORD = "Acme026512"
TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"

def extract_flag():
    key_entry = f'"wpa-pwd", "{PASSWORD}:{SSID}"'

    cmd = [
        TSHARK,
        "-r", PCAP_FILE,
        "-o", "wlan.enable_decryption:TRUE",
        "-o", f"uat:80211_keys:{key_entry}",
        "-Y", "http",
        "-T", "fields",
        "-e", "http.file_data"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    for line in result.stdout.strip().split("\n"):
        hex_data = line.strip()
        if not hex_data:
            continue

        try:
            text = bytes.fromhex(hex_data).decode("utf-8", errors="ignore")
            match = re.search(r"netsec\{[a-f0-9]+\}", text)
            if match:
                flag = match.group(0)
                print(f"Decrypted payload: {text.strip()}")
                return flag
        
        except ValueError:
            continue
    
    return None

if __name__ == "__main__":
    flag = extract_flag()
    print(f"Flag: {flag}")