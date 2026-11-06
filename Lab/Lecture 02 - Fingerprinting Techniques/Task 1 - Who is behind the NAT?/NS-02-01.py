import dpkt
import socket
import struct

PCAP_FILE = "capture-6.pcap"
NAT_IP = "198.51.100.7"
HZ = 250.0
TOLERANCE = 100

def extract_tsval(tcp):
    opts = dpkt.tcp.parse_opts(tcp.opts)

    for opt_type, opt_val in opts:
        if opt_type == dpkt.tcp.TCP_OPT_TIMESTAMP:
            tsval, tsecr = struct.unpack(">II", opt_val)
            return tsval
    
    return None

def find_anchor(pcap_path):
    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            src_ip = socket.inet_ntoa(ip.src)

            if src_ip == NAT_IP and b"POST /admin/login" in tcp.data:
                tsval = extract_tsval(tcp)

                print(f"Login packet found.")
                print(f"Time (t): {ts}")
                print(f"Source Port: {tcp.sport}")
                print(f"TSval: {tsval}")

                return ts, tsval, tcp.sport

def find_admin_ports(pcap_path, t_anchor, ts_anchor):
    admin_ports = set()

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            src_ip = socket.inet_ntoa(ip.src)
            if src_ip != NAT_IP:
                continue
            
            tsval = extract_tsval(tcp)

            if tsval is not None:
                expected_tsval = ts_anchor + HZ * (ts - t_anchor)
                if abs(tsval - expected_tsval) <= TOLERANCE:
                    admin_ports.add(tcp.sport)

    return admin_ports

def extract_flag(pcap_path, admin_ports):
    pieces = {}

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            src_ip = socket.inet_ntoa(ip.src)

            if src_ip == NAT_IP and tcp.sport in admin_ports:
                if b"X-Trace:" in tcp.data:
                    text = tcp.data.decode("utf-8", errors="ignore")

                    for line in text.split("\r\n"):
                        if line.lower().startswith("x-trace:"):
                            _, value = line.split(":", 1)
                            value = value.strip()
                            n_str, hex_piece = value.split("-", 1)
                            n = int(n_str)
                            pieces[n] = hex_piece

        print("\nCollected pieces:")
        for n in sorted(pieces.keys()):
            print(f"{n}:{pieces[n]}")

        token = "".join(pieces[i] for i in range(1,9))
        flag = f"netsec{{{token}}}"


    return flag

if __name__ == "__main__":
    t_anchor, ts_anchor, anchor_port = find_anchor(PCAP_FILE)
    admin_ports = find_admin_ports(PCAP_FILE, t_anchor, ts_anchor)
    flag = extract_flag(PCAP_FILE, admin_ports)

    print(f"\nFlag: {flag}")