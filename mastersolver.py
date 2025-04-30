
import angr
import claripy
from pwn import *
import subprocess
import re
import sys

def solve_crackme100():
    print("\n[*] Solving crackme100...")
    project = angr.Project("./crackme100", auto_load_libs=False)

    input_len = 50
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(input_len)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    state = project.factory.full_init_state(
        stdin=flag,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )

    for k in flag_chars:
        state.solver.add(k >= 0x20)
        state.solver.add(k <= 0x7e)

    simgr = project.factory.simgr(state)

    SUCCESS_ADDR = 0x401378
    FAILURE_ADDR = 0x401389

    print("[*] Exploring...")
    simgr.explore(find=SUCCESS_ADDR, avoid=FAILURE_ADDR)

    if not simgr.found:
        print("[-] No solution found.")
        return

    found_state = simgr.found[0]
    password_bytes = found_state.solver.eval(flag, cast_to=bytes)
    password_str = password_bytes.strip().decode('utf-8')

    print(f"[+] Found password: {password_str}")

    # Send password
    proc = subprocess.Popen(
        ['./crackme100'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    stdout, stderr = proc.communicate(input=password_str.encode() + b'\n')
    stdout_decoded = stdout.decode('utf-8', errors='ignore')
    print(f"[*] Binary output:\n{stdout_decoded}")

    # Extract encoded output
    encoded_output = None
    for line in stdout_decoded.splitlines():
        if line.strip() and "SUCCESS" not in line.upper():
            encoded_output = line.strip()
            break

    if not encoded_output:
        print("[-] No encoded output found.")
        return

    # Decode
    print("[*] Decoding output...")
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


def solve_pietime(remote=False, host=None, port=None):
    print("\n[*] Solving pietime...")
    project = angr.Project("./pietime", auto_load_libs=False)
    main_offset = project.loader.main_object.get_symbol('main').relative_addr
    win_offset = project.loader.main_object.get_symbol('win').relative_addr

    print(f"[+] main offset: {hex(main_offset)}")
    print(f"[+] win offset:  {hex(win_offset)}")

    if remote:
        conn = remote(host, port)
    else:
        conn = process("./pietime")

    received = conn.recvline_contains(b"Address of main:").decode()
    match = re.search(r'0x[0-9a-f]+', received)
    if not match:
        print("[-] Couldn't parse address.")
        return

    main_runtime_addr = int(match.group(0), 16)
    real_base = main_runtime_addr - main_offset
    real_win_addr = real_base + win_offset
    print(f"[+] Jumping to win() at: {hex(real_win_addr)}")

    conn.recvuntil(b"Enter the address")
    conn.sendline(hex(real_win_addr).encode())

    result = conn.recvall(timeout=5)
    print(f"\nFinal Output:\n{result.decode(errors='ignore')}")
    conn.close()


def solve_perplexed():
    print("\n[*] Solving perplexed...")
    project = angr.Project('./perplexed', auto_load_libs=False)

    input_len = 27
    input_chars = [claripy.BVS(f'chr_{i}', 8) for i in range(input_len)]
    password = claripy.Concat(*input_chars)

    state = project.factory.full_init_state(stdin=password)

    for c in input_chars:
        state.solver.add(c >= 0x00)
        state.solver.add(c <= 0x7f)

    FIND_ADDR = 0x401439
    AVOID_ADDR = 0x401428

    simgr = project.factory.simgr(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if not simgr.found:
        print("[-] No solution found.")
        return

    found = simgr.found[0]
    flag = found.solver.eval(password, cast_to=bytes)
    print(f"Found password:\n{repr(flag)}")


if __name__ == "__main__":
    print("Select which challenge to solve:")
    print("1. crackme100")
    print("2. pietime")
    print("3. perplexed")

    choice = input("> ").strip()

    if choice == "1":
        solve_crackme100()
    elif choice == "2":
        remote = input("Remote? (y/n): ").strip().lower() == 'y'
        if remote:
            host = input("Enter host: ").strip()
            port = int(input("Enter port: ").strip())
            solve_pietime(remote=True, host=host, port=port)
        else:
            solve_pietime()
    elif choice == "3":
        solve_perplexed()
    else:
        print("Invalid choice. Exiting.")