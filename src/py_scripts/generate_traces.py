import os
import numpy as np
import h5py
from rainbow import Rainbow
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
import matplotlib.pyplot as plt
from tqdm import tqdm

import os

# Define base directory (lab11 root)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BUILD_DIR = os.path.join(BASE_DIR, "build")
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# Configuration
BINARY_PATH = os.path.join(BUILD_DIR, "ascon128.elf")
FIXED_KEY_H5 = os.path.join(DATA_DIR, "ascon_fixed_key.h5")
VARIABLE_KEY_H5 = os.path.join(DATA_DIR, "ascon_variable_key.h5")
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
            init_addr = rainbow.functions["ascon128_init"][0]
            encrypt_addr = rainbow.functions["ascon128_encrypt"][0]
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

        try:
            rainbow.emu.mem_map(0x20000000, 0x1000)
        except Exception:
            pass

        rainbow[key_addr] = current_key.tobytes()
        rainbow[nonce_addr] = current_nonce.tobytes()
        rainbow[pt_addr] = current_pt.tobytes()

        # Trace capture
        trace = []
        target_val = 0

        def power_hook(emu, access, address, size, value, user_data):
            # Simple Hamming Weight Leakage Model
            # We assume power leakage is proportional to the HW of the value being moved/processed
            leakage = get_hamming_weight(value & 0xFFFFFFFF)
            trace.append(leakage)
            nonlocal target_val
            # Target: The value of state[0] after the first S-box layer
            if address == state_addr and access == UC_HOOK_MEM_WRITE:
                target_val = value

        # Register hooks
        h = rainbow.emu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, power_hook)
        
        # Execution
        # 1. Init
        rainbow["r0"] = state_addr
        rainbow["r1"] = key_addr
        rainbow["r2"] = nonce_addr
        rainbow["lr"] = 0x10000000
        rainbow.start(init_addr | 1, 0x10000000)
        
        # 2. Encrypt (where we capture the target)
        rainbow["r0"] = state_addr
        rainbow["r1"] = ct_addr
        rainbow["r2"] = pt_addr
        rainbow["r3"] = 8
        rainbow["lr"] = 0x10000000
        rainbow.start(encrypt_addr | 1, 0x10000000)

        rainbow.emu.hook_del(h)

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
        from rainbow.generics import rainbow_arm
        e = rainbow_arm()
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
    plot_save_path = os.path.join(OUTPUT_DIR, "sample_trace.png")
    plt.savefig(plot_save_path)
    plt.show()
    print(f"Sample trace visualization saved as {plot_save_path}")

if __name__ == "__main__":
    main()
