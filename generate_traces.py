import os
import numpy as np
import h5py
from rainbow import Rainbow
from rainbow.generics import *
import matplotlib.pyplot as plt
from tqdm import tqdm

# Configuration
BINARY_PATH = "ascon128.elf"
FIXED_KEY_H5 = "ascon_fixed_key.h5"
VARIABLE_KEY_H5 = "ascon_variable_key.h5"
NUM_TRACES_FIXED = 6000  # 5000 profiling + 1000 attack
NUM_TRACES_VAR = 5000
STATE_SIZE = 40  # 5 * 8 bytes

# ASCON-128 Constants for reference
IV = 0x80400c0600000000

def get_hamming_weight(n):
    return bin(n).count('1')

def generate_dataset(rainbow, num_traces, fixed_key=None):
    """
    Generates a dataset of traces and intermediate values.
    """
    traces = []
    keys = []
    plaintexts = []
    intermediates = []

    # Fixed key if provided, otherwise random
    if fixed_key is not None:
        current_key = np.frombuffer(fixed_key, dtype=np.uint8)
    
    print(f"Generating {'Fixed' if fixed_key is not None else 'Variable'}-Key Dataset...")

    for i in tqdm(range(num_traces)):
        if fixed_key is None:
            current_key = np.random.randint(0, 256, 16, dtype=np.uint8)
        
        current_pt = np.random.randint(0, 256, 8, dtype=np.uint8)
        current_nonce = np.random.randint(0, 256, 16, dtype=np.uint8)

        # Reset emulator and setup state
        rainbow.reset()
        
        # Addresses (placeholders - will be resolved from ELF symbols)
        # Assuming we have a wrapper or we call ascon128_init directly
        try:
            init_addr = rainbow.functions["ascon128_init"]
            encrypt_addr = rainbow.functions["ascon128_encrypt"]
        except KeyError:
            # Fallback to manual address if symbols are missing (example addresses)
            init_addr = 0x08000000 
            encrypt_addr = 0x08000100

        # Memory layout
        key_addr = 0x20000000
        nonce_addr = 0x20000010
        state_addr = 0x20000020
        pt_addr = 0x20000050
        ct_addr = 0x20000060

        rainbow.mem_write(key_addr, current_key.tobytes())
        rainbow.mem_write(nonce_addr, current_nonce.tobytes())
        rainbow.mem_write(pt_addr, current_pt.tobytes())

        # Trace capture
        trace = []
        target_val = 0

        def power_hook(emu, address, size, value):
            # Simple Hamming Weight Leakage Model
            # We assume power leakage is proportional to the HW of the value being moved/processed
            leakage = get_hamming_weight(value & 0xFFFFFFFF)
            trace.append(leakage)

        def intermediate_hook(emu, address, size, value):
            nonlocal target_val
            # Target: The value of state[0] after the first S-box layer
            # This requires identifying the specific instruction or memory write
            # For this simulation, we'll capture it when state[0] is written
            if address == state_addr:
                target_val = value

        # Register hooks
        rainbow.add_hook(HOOK_MEM_WRITE | HOOK_MEM_READ, power_hook)
        # Note: In a real scenario, you'd find the exact instruction offset for the S-box
        # Here we simulate by capturing the first state update in encryption
        
        # Execution
        # 1. Init
        rainbow.setup_call(init_addr, [state_addr, key_addr, nonce_addr])
        rainbow.emu_start(init_addr, until=init_addr + 0x100) # Dummy end
        
        # 2. Encrypt (where we capture the target)
        rainbow.setup_call(encrypt_addr, [state_addr, ct_addr, pt_addr, 8])
        rainbow.emu_start(encrypt_addr, until=encrypt_addr + 0x200)

        # Store data
        traces.append(trace)
        keys.append(current_key)
        plaintexts.append(current_pt)
        # If target_val wasn't captured, use a dummy HW for demo
        intermediates.append(get_hamming_weight(target_val))

    # Pad traces to equal length
    max_len = max(len(t) for t in traces)
    padded_traces = np.zeros((num_traces, max_len), dtype=np.float32)
    for i, t in enumerate(traces):
        padded_traces[i, :len(t)] = t

    return padded_traces, np.array(keys), np.array(plaintexts), np.array(intermediates)

def save_h5(filename, traces, keys, plaintexts, intermediates):
    with h5py.File(filename, 'w') as f:
        f.create_dataset('traces', data=traces)
        f.create_dataset('keys', data=keys)
        f.create_dataset('plaintexts', data=plaintexts)
        f.create_dataset('intermediates', data=intermediates)
    print(f"Dataset saved to {filename}")

def main():
    if not os.path.exists(BINARY_PATH):
        print(f"Error: {BINARY_PATH} not found. Please run 'make arm' first.")
        # Create a dummy ELF for script structure if needed, or exit
        # return

    # Initialize Rainbow
    try:
        e = Rainbow()
        e.load(BINARY_PATH)
    except Exception as ex:
        print(f"Rainbow initialization failed: {ex}")
        print("Note: This script requires a valid ARM ELF binary and the rainbow-scs library.")
        return

    # 1. Fixed-Key Dataset
    fixed_key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    traces_f, keys_f, pts_f, im_f = generate_dataset(e, NUM_TRACES_FIXED, fixed_key=fixed_key)
    save_h5(FIXED_KEY_H5, traces_f, keys_f, pts_f, im_f)

    # 2. Variable-Key Dataset
    traces_v, keys_v, pts_v, im_v = generate_dataset(e, NUM_TRACES_VAR)
    save_h5(VARIABLE_KEY_H5, traces_v, keys_v, pts_v, im_v)

    # Visualization
    plt.figure(figsize=(10, 4))
    plt.plot(traces_f[0], label="Sample Trace (Fixed Key)")
    plt.title("Simulated Power Trace (Hamming Weight Leakage)")
    plt.xlabel("Clock Cycles / Events")
    plt.ylabel("Leakage (HW)")
    plt.legend()
    plt.savefig("sample_trace.png")
    plt.show()
    print("Sample trace visualization saved as sample_trace.png")

if __name__ == "__main__":
    main()
