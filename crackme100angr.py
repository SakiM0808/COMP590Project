
import angr
import claripy
import subprocess

#  Find password using angr
print("[*] Running angr to solve password...")

# Load the binary
project = angr.Project("./crackme100", auto_load_libs=False)

# Create symbolic stdin input (50 bytes + newline)
input_len = 50
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(input_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

state = project.factory.full_init_state(
    stdin=flag,
    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
)

# Apply printable ASCII constraints
for k in flag_chars:
    state.solver.add(k >= 0x20)
    state.solver.add(k <= 0x7e)

# Simulation manager
simgr = project.factory.simgr(state)

# Addresses (found from Ghidra)
SUCCESS_ADDR = 0x401378  # Success message
FAILURE_ADDR = 0x401389  # Failure message

print("[*] Exploring...")
simgr.explore(find=SUCCESS_ADDR, avoid=FAILURE_ADDR)

if not simgr.found:
    print("[-] No solution found.")
    exit(1)

found_state = simgr.found[0]
password_bytes = found_state.solver.eval(flag, cast_to=bytes)
password_str = password_bytes.strip().decode('utf-8')  # Remove \n and decode

print(f"[+] Found password: {password_str}")

# Run crackme100 with the solved password
print("[*] Sending password to crackme100...")

# Use subprocess to send input and capture output
proc = subprocess.Popen(
    ['./crackme100'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

stdout, stderr = proc.communicate(input=password_str.encode() + b'\n')

# Decode stdout
stdout_decoded = stdout.decode('utf-8', errors='ignore')
print(f"[*] Raw binary output:\n{stdout_decoded}")

# Extract encoded string
encoded_output = None
for line in stdout_decoded.splitlines():
    if line.strip() and "SUCCESS" not in line.upper():
        encoded_output = line.strip()
        break

if not encoded_output:
    print("[-] No encoded output found.")
    exit(1)

print(f"[+] Captured encoded output: {encoded_output}")

# Decode the printed output manually 
print("[*] Decoding final flag...")

c = encoded_output
p = ['' for _ in c]

for i in range(3):
    for j in range(len(c)):
        v7 = (85 & (j % 255)) + (85 & ((j % 255) >> 1))
        v6 = (v7 & 51) + (51 & (v7 >> 2))
        x = (ord(c[j]) - 97) % 26
        y = (x - ((v6 & 15) + (15 & (v6 >> 4)))) % 26
        p[j] = chr(y + 97)

    c = ''.join(p)

print(f"Final Decoded Flag: {c}")
