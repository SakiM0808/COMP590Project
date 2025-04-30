import angr
import claripy


# Load binary
project = angr.Project('./perplexed', auto_load_libs=False)


input_len = 27 #Found on Ghidra
input_chars = [claripy.BVS(f'chr_{i}', 8) for i in range(input_len)]
password = claripy.Concat(*input_chars)


# Set up state with symbolic stdin
state = project.factory.full_init_state(stdin=password)


# apply the ASCII constraint
for c in input_chars:
    state.solver.add(c >= 0x00)
    state.solver.add(c <= 0x7f)



FIND_ADDR = 0x401439    #  success address found on ghidra
AVOID_ADDR = 0x401428   # failure address found on ghidra


# Explore
simgr = project.factory.simgr(state)
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)


# print solution
if simgr.found:
    found = simgr.found[0]
    flag = found.solver.eval(password, cast_to=bytes)
    print(password);
    print(repr(flag))
else:
    print("No solution found.")

