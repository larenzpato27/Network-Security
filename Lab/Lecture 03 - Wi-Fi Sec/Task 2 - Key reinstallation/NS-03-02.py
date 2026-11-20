import dpkt
import re
PCAP_FILE = "capture-6.pcap"
EXPENSE_FORM_FILE = "expense-form.txt"

def load_expense_form(path):
    with open(path, "rb") as f:
        return f.read()

def get_frames(pcap_path):
    frame_upload = None
    frame_login = None

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for i, (ts, buf) in enumerate(pcap, start=1):
            if i == 290:
                frame_upload = buf
            elif i == 479:
                frame_login = buf
        
        return frame_upload, frame_login

def decrypt_login(frame_upload, frame_login, expense_form):
    rt_len_upload = int.from_bytes(frame_upload[2:4], "little")
    rt_len_login = int.from_bytes(frame_login[2:4], "little")

    enc_upload = frame_upload[rt_len_upload+32:]
    enc_login = frame_login[rt_len_login+32:]

    payload_offset = 48
    login_payload_len = len(enc_login) - payload_offset - 8

    keystream = bytearray()
    for i in range(login_payload_len):
        k = enc_upload[payload_offset + i] ^ expense_form[i]
        keystream.append(k)

    decrypted_bytes = bytearray()
    for i in range(login_payload_len):
        p = enc_login[payload_offset + i] ^ keystream[i]
        decrypted_bytes.append(p)

    return decrypted_bytes.decode("ascii", errors="ignore")

if __name__ == "__main__":
    expense_form = load_expense_form(EXPENSE_FORM_FILE)
    frame_upload, frame_login = get_frames(PCAP_FILE)
    
    decrypyed_text = decrypt_login(frame_upload, frame_login, expense_form)
    print("Decrypted Login Request:")
    print(decrypyed_text.strip())

    match = re.search(r"netsec\{[0-9a-fA-F]+\}", decrypyed_text)
    if match:
        flag = match.group(0)
        print(f"\nFlag: {flag}")