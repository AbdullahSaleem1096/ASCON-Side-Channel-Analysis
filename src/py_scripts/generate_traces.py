"""
generate_traces.py  –  ASCON-128 SCA trace generation (corrected)

Key fixes vs previous version:
  - Pure-Python ASCON reference (no Rainbow emulation dependency)
  - Label = HW(target_byte) where target_byte is ONE byte of state[0]
    after p12, giving 9 classes (0-8), not directly present in the trace
  - Trace = HW of each 64-bit state word at every round step (genuine leakage)
  - Fixed-key dataset : same key, random nonces
  - Variable-key dataset: random keys AND random nonces
"""

import os
import numpy as np
import h5py
import matplotlib.pyplot as plt
from tqdm import tqdm

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR   = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(DATA_DIR,   exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

FIXED_KEY_H5    = os.path.join(DATA_DIR, "ascon_fixed_key.h5")
VARIABLE_KEY_H5 = os.path.join(DATA_DIR, "ascon_variable_key.h5")
NUM_TRACES_FIXED = 6000   # 5000 profiling + 1000 attack
NUM_TRACES_VAR   = 5000   # 4000 profiling + 1000 attack (unseen keys)
FIXED_KEY = bytes(range(16))   # 0x00 … 0x0f

# ── ASCON-128 Python Reference ─────────────────────────────────────────────────
RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
M64 = 0xFFFFFFFFFFFFFFFF

def rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & M64

def load64be(b, offset=0):
    return int.from_bytes(b[offset:offset + 8], 'big')

def ascon_permutation(state, rounds, leakage=None):
    """
    Run the ASCON permutation.
    If `leakage` is a list, appends HW(word) for all 5 words after the
    S-box and after the linear-diffusion layer of every round.
    Returns the new state as a list of 5 uint64.
    """
    x = list(state)
    start = 12 - rounds
    for i in range(start, 12):
        # 1. Round constant
        x[2] ^= RC[i]

        # 2. S-box layer
        x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1]
        t0 = (~x[0] & x[1]) & M64
        t1 = (~x[1] & x[2]) & M64
        t2 = (~x[2] & x[3]) & M64
        t3 = (~x[3] & x[4]) & M64
        t4 = (~x[4] & x[0]) & M64
        x[0] ^= t1; x[1] ^= t2; x[2] ^= t3; x[3] ^= t4; x[4] ^= t0
        x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]
        x[2] = (~x[2]) & M64

        # Record HW leakage after S-box
        if leakage is not None:
            for w in x:
                leakage.append(bin(w).count('1'))

        # 3. Linear diffusion layer
        x[0] = (x[0] ^ rotr64(x[0], 19) ^ rotr64(x[0], 28)) & M64
        x[1] = (x[1] ^ rotr64(x[1], 61) ^ rotr64(x[1], 39)) & M64
        x[2] = (x[2] ^ rotr64(x[2],  1) ^ rotr64(x[2],  6)) & M64
        x[3] = (x[3] ^ rotr64(x[3], 10) ^ rotr64(x[3], 17)) & M64
        x[4] = (x[4] ^ rotr64(x[4],  7) ^ rotr64(x[4], 41)) & M64

        # Record HW leakage after linear diffusion
        if leakage is not None:
            for w in x:
                leakage.append(bin(w).count('1'))

    return x


def ascon128_simulate(key: bytes, nonce: bytes):
    """
    Run ASCON-128 initialisation phase only (sufficient for profiling attack).
    Returns:
        trace              – numpy float32 array of HW leakage samples
        target_byte        – byte 0 (MSB) of state[0] immediately after p12
                             (BEFORE the final key XOR).  This is the attack
                             intermediate: it depends on key+nonce but is NOT
                             stored directly in the trace (trace stores HW of
                             full 64-bit words, not individual bytes).
    """
    IV = 0x80400c0600000000
    k0 = load64be(key, 0);  k1 = load64be(key, 8)
    n0 = load64be(nonce, 0); n1 = load64be(nonce, 8)

    state = [IV, k0, k1, n0, n1]
    leakage = []

    # p12 – this is where we capture the trace
    state = ascon_permutation(state, 12, leakage=leakage)

    # Target intermediate: MSB of state[0] right after p12
    # Label = HW(this byte) → 0 … 8  (9 classes)
    target_byte = (state[0] >> 56) & 0xFF

    # Complete init (key XOR) – not included in trace for simplicity
    state[3] = (state[3] ^ k0) & M64
    state[4] = (state[4] ^ k1) & M64

    return np.array(leakage, dtype=np.float32), target_byte


def hw(b):
    return bin(b).count('1')


def generate_dataset(num_traces, fixed_key=None):
    traces, labels, keys, nonces = [], [], [], []
    desc = "Fixed-Key" if fixed_key is not None else "Variable-Key"
    for _ in tqdm(range(num_traces), desc=f"Generating {desc} traces"):
        key   = fixed_key if fixed_key is not None \
                else bytes(np.random.randint(0, 256, 16, dtype=np.uint8))
        nonce = bytes(np.random.randint(0, 256, 16, dtype=np.uint8))

        trace, t_byte = ascon128_simulate(key, nonce)
        traces.append(trace)
        labels.append(hw(t_byte))   # 0–8
        keys.append(list(key))
        nonces.append(list(nonce))

    return (np.array(traces,  dtype=np.float32),
            np.array(labels,  dtype=np.int32),
            np.array(keys,    dtype=np.uint8),
            np.array(nonces,  dtype=np.uint8))


def save_h5(path, traces, labels, keys, nonces):
    with h5py.File(path, 'w') as f:
        f.create_dataset('traces',  data=traces)
        f.create_dataset('labels',  data=labels)   # HW of target byte, 0-8
        f.create_dataset('keys',    data=keys)
        f.create_dataset('nonces',  data=nonces)
    print(f"Saved {path}  shape={traces.shape}  label_range=[{labels.min()},{labels.max()}]")


def main():
    print(f"Trace length = {12 * 2 * 5} samples (12 rounds × 2 points × 5 words)\n")

    # ── Fixed-key dataset ──────────────────────────────────────────────────────
    tr_f, lb_f, k_f, n_f = generate_dataset(NUM_TRACES_FIXED, fixed_key=FIXED_KEY)
    save_h5(FIXED_KEY_H5, tr_f, lb_f, k_f, n_f)

    # ── Variable-key dataset ───────────────────────────────────────────────────
    tr_v, lb_v, k_v, n_v = generate_dataset(NUM_TRACES_VAR)
    save_h5(VARIABLE_KEY_H5, tr_v, lb_v, k_v, n_v)

    # ── Visualise 10 sample traces ──────────────────────────────────────────────
    fig, axes = plt.subplots(2, 5, figsize=(18, 6))
    fig.suptitle("Sample Power Traces – ASCON-128 Init (HW Leakage Model)", fontsize=13)
    for idx, ax in enumerate(axes.flat):
        ax.plot(tr_f[idx], linewidth=0.8)
        ax.set_title(f"Trace {idx+1}  |  label={lb_f[idx]}")
        ax.set_xlabel("Sample index"); ax.set_ylabel("HW")
    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "10_sample_traces.png")
    plt.savefig(out, dpi=120); plt.close()
    print(f"\nSaved {out}")

    # Single trace
    plt.figure(figsize=(10, 4))
    plt.plot(tr_f[0], color='steelblue', linewidth=0.9)
    plt.title("Sample Power Trace – Fixed Key, Trace 0")
    plt.xlabel("Sample index (round × layer × word)")
    plt.ylabel("Hamming Weight leakage")
    plt.tight_layout()
    out2 = os.path.join(OUTPUT_DIR, "sample_trace.png")
    plt.savefig(out2, dpi=120); plt.close()
    print(f"Saved {out2}")


if __name__ == "__main__":
    main()
