import subprocess
import shutil

PCAP_FILE = "capture-6.pcap"

TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"

def extract_flag():
    cmd = [
        TSHARK,
        "-r", PCAP_FILE,
        "-Y", "tls.handshake.type == 1",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.ja4"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    connections = []
    target_ja4 = None

    for line in result.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) == 3:
            ts, sni, ja4 = parts
            connections.append((float(ts), sni, ja4))

            if "syncbridge.example" in sni:
                target_ja4 = ja4
                print(f"Anchor found: SNI = {sni}")
                print(f"Malware JA4 = {target_ja4}\n")

    malware_conns = []
    for ts, sni, ja4 in connections:
        if ja4 == target_ja4:
            malware_conns.append(sni)

    print(f"Total malware connections found: {len(malware_conns)}")

    labels = []
    for sni in malware_conns:
        first_label = sni.split(".")[0]
        labels.append(first_label)
        print(f"{sni} (label: {first_label})")

    token = "".join(labels)
    flag = f"netsec{{{token}}}"
    return flag

if __name__ == "__main__":
    flag = extract_flag()
    print(f"\nFlag: {flag}")