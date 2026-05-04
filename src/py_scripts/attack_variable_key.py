"""
attack_variable_key.py  –  Deep-learning SCA on the ASCON-128 Variable-Key dataset

Target    : byte 0 (MSB) of state[0] after p12 init permutation
Label     : HW(target_byte)  →  classes 0 … 8  (NUM_CLASSES = 9)
Split     : 4000 profiling traces (random keys)
            1000 attack  traces  (random keys – statistically unseen;
                                  P(collision with any profiling key) ≈ 0)

Expected accuracy: 15–30 %  — significantly lower than the fixed-key attack
because the model must generalise across unseen keys.  This demonstrates
the genuine difficulty of cross-device / cross-key SCA generalisation.
"""

import os, h5py
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (Conv1D, MaxPooling1D, Flatten,
                                     Dense, Dropout, BatchNormalization)
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

NUM_CLASSES    = 9   # HW of a single byte: 0 … 8
NUM_PROFILING  = 4000
EPOCHS         = 50
BATCH_SIZE     = 64
SEED           = 42
tf.random.set_seed(SEED); np.random.seed(SEED)

# ── 1. Load dataset ────────────────────────────────────────────────────────────
h5_path = os.path.join(DATA_DIR, "ascon_variable_key.h5")
print(f"Loading {h5_path} …")
with h5py.File(h5_path, 'r') as f:
    traces = np.array(f['traces'])   # shape (5000, 120)
    labels = np.array(f['labels'])   # shape (5000,)  values 0–8
    keys   = np.array(f['keys'])     # shape (5000, 16)

print(f"  traces : {traces.shape}   dtype={traces.dtype}")
print(f"  labels : {labels.shape}   unique={np.unique(labels)}")

# Verify key uniqueness between profiling and attack splits
profiling_keys = set(map(tuple, keys[:NUM_PROFILING]))
attack_keys    = set(map(tuple, keys[NUM_PROFILING:]))
overlap = profiling_keys & attack_keys
print(f"\n  Key overlap between profiling and attack sets: {len(overlap)} "
      f"(expected ≈ 0 for random 128-bit keys)")

# ── 2. Normalise ───────────────────────────────────────────────────────────────
scaler = StandardScaler()
traces_norm = scaler.fit_transform(traces)
traces_cnn  = traces_norm.reshape(len(traces_norm), -1, 1)
labels_cat  = to_categorical(labels, num_classes=NUM_CLASSES)

# ── 3. Profiling / attack split ────────────────────────────────────────────────
x_train = traces_cnn[:NUM_PROFILING]
y_train = labels_cat[:NUM_PROFILING]
x_test  = traces_cnn[NUM_PROFILING:]
y_test  = labels_cat[NUM_PROFILING:]
print(f"\nProfiling set : {x_train.shape[0]} traces  (random keys)")
print(f"Attack set    : {x_test.shape[0]} traces   (unseen random keys)")

# ── 4. CNN model (same architecture as fixed-key for fair comparison) ──────────
model = Sequential([
    Conv1D(32, kernel_size=5, activation='relu', padding='same',
           input_shape=(x_train.shape[1], 1)),
    BatchNormalization(),
    MaxPooling1D(pool_size=2),

    Conv1D(64, kernel_size=5, activation='relu', padding='same'),
    BatchNormalization(),
    MaxPooling1D(pool_size=2),

    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.3),
    Dense(NUM_CLASSES, activation='softmax'),
], name="cnn_variable_key")

model.compile(optimizer='adam',
              loss='categorical_crossentropy',
              metrics=['accuracy'])
model.summary()

# ── 5. Train ───────────────────────────────────────────────────────────────────
callbacks = [
    EarlyStopping(monitor='val_accuracy', patience=10, restore_best_weights=True),
    ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6),
]
history = model.fit(
    x_train, y_train,
    epochs=EPOCHS, batch_size=BATCH_SIZE,
    validation_data=(x_test, y_test),
    callbacks=callbacks, verbose=1,
)

# ── 6. Evaluate ────────────────────────────────────────────────────────────────
loss, accuracy = model.evaluate(x_test, y_test, verbose=0)
fixed_key_ref  = None   # placeholder – compare manually if you have it
print(f"\n{'='*60}")
print(f"Variable-Key Generalisation Accuracy : {accuracy*100:.2f}%")
print(f"(Random-guess baseline               : {100/NUM_CLASSES:.2f}%)")
print(f"{'='*60}")
print("\n  NOTE: Lower accuracy than fixed-key attack is EXPECTED.")
print("  The model must generalise to completely unseen 128-bit keys.")
print("  Any accuracy above the random baseline indicates genuine HW leakage.")

y_pred = np.argmax(model.predict(x_test), axis=1)
y_true = np.argmax(y_test, axis=1)
print("\nClassification report:\n")
print(classification_report(y_true, y_pred,
                             target_names=[f"HW={i}" for i in range(NUM_CLASSES)]))

# ── 7. Key rank analysis ───────────────────────────────────────────────────────
probs = model.predict(x_test)
cum_log_prob = np.zeros(NUM_CLASSES)
key_ranks = []
for i in range(len(x_test)):
    cum_log_prob += np.log(probs[i] + 1e-36)
    rank = NUM_CLASSES - 1 - np.argsort(cum_log_prob).tolist().index(y_true[i])
    key_ranks.append(rank)

plt.figure(figsize=(8, 4))
plt.plot(key_ranks)
plt.axhline(0, color='red', linestyle='--', label='Rank 0 (correct)')
plt.title("Key Rank over Attack Traces (Variable Key)")
plt.xlabel("Number of attack traces"); plt.ylabel("Key rank")
plt.legend(); plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "variable_key_rank.png"), dpi=120)
plt.close()

# ── 8. Training history plot ───────────────────────────────────────────────────
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
ax1.plot(history.history['loss'],     label='Train Loss')
ax1.plot(history.history['val_loss'], label='Val Loss')
ax1.set_title('Loss – Variable Key'); ax1.legend()
ax2.plot(history.history['accuracy'],     label='Train Acc')
ax2.plot(history.history['val_accuracy'], label='Val Acc')
ax2.axhline(1/NUM_CLASSES, color='gray', linestyle=':', label='Random baseline')
ax2.set_title('Accuracy – Variable Key'); ax2.legend()
fig.tight_layout()
hist_path = os.path.join(OUTPUT_DIR, "variable_key_history.png")
plt.savefig(hist_path, dpi=120); plt.close()
print(f"\nPlots saved to {OUTPUT_DIR}")

# ── 9. Save model ──────────────────────────────────────────────────────────────
model_path = os.path.join(MODELS_DIR, "model_variable_key.h5")
model.save(model_path)
print(f"Model saved to {model_path}")
