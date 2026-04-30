import h5py
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

# 1. Load Data
with h5py.File('ascon_variable_key.h5', 'r') as f:
    traces = np.array(f['traces'])
    labels = np.array(f['intermediates'])

NUM_CLASSES = 33

# 2. Preprocess Data
scaler = StandardScaler()
traces_normalized = scaler.fit_transform(traces)

# Reshape for Conv1D: (samples, time_steps, features)
traces_reshaped = traces_normalized.reshape((traces_normalized.shape[0], traces_normalized.shape[1], 1))
labels_categorical = to_categorical(labels, num_classes=NUM_CLASSES)

# 3. Split Dataset (4000 profiling, 1000 attack)
num_profiling = 4000
x_train = traces_reshaped[:num_profiling]
y_train = labels_categorical[:num_profiling]

x_test = traces_reshaped[num_profiling:]
y_test = labels_categorical[num_profiling:]

# 4. Build CNN Model
model = Sequential([
    Conv1D(filters=32, kernel_size=11, activation='relu', input_shape=(x_train.shape[1], 1)),
    MaxPooling1D(pool_size=2),
    Conv1D(filters=64, kernel_size=11, activation='relu'),
    MaxPooling1D(pool_size=2),
    Flatten(),
    Dense(128, activation='relu'),
    Dense(NUM_CLASSES, activation='softmax')
])

model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# 5. Train Model
history = model.fit(x_train, y_train, epochs=20, batch_size=64, validation_data=(x_test, y_test), verbose=1)

# 6. Evaluate Attack
loss, accuracy = model.evaluate(x_test, y_test, verbose=0)
print(f"Variable-Key Attack Success Rate (Generalization Accuracy): {accuracy * 100:.2f}%")

# Save model
model.save('model_variable_key.h5')

# Plot training history
plt.figure(figsize=(12, 5))
plt.subplot(1, 2, 1)
plt.plot(history.history['loss'], label='Train Loss')
plt.plot(history.history['val_loss'], label='Val Loss')
plt.title('Loss over Epochs (Variable Key)')
plt.legend()

plt.subplot(1, 2, 2)
plt.plot(history.history['accuracy'], label='Train Accuracy')
plt.plot(history.history['val_accuracy'], label='Val Accuracy')
plt.title('Accuracy over Epochs (Variable Key)')
plt.legend()
plt.savefig('variable_key_history.png')
print("Saved variable_key_history.png")
