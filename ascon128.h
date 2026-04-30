#ifndef ASCON128_H
#define ASCON128_H

#include <stdint.h>
#include <stddef.h>

/**
 * ASCON-128 parameters
 * k = 128 (Key size)
 * r = 64  (Rate)
 * a = 12  (Initialization and Finalization rounds)
 * b = 6   (Intermediate rounds)
 */

typedef struct {
    uint64_t x[5];
} ascon_state_t;

/**
 * Initialize ASCON state with key and nonce.
 */
void ascon128_init(ascon_state_t *state, const uint8_t *key, const uint8_t *nonce);

/**
 * Process associated data.
 */
void ascon128_ad(ascon_state_t *state, const uint8_t *ad, size_t adlen);

/**
 * Encrypt plaintext to ciphertext.
 * Returns the length of ciphertext (including padding if handled internally, but here we follow AEAD).
 */
void ascon128_encrypt(ascon_state_t *state, uint8_t *ciphertext, const uint8_t *plaintext, size_t len);

/**
 * Finalize encryption and generate tag.
 * Tag must be 16 bytes.
 */
void ascon128_finalize(ascon_state_t *state, const uint8_t *key, uint8_t *tag);

/**
 * Decrypt ciphertext to plaintext.
 * Note: In a real AEAD, this would also verify the tag.
 */
void ascon128_decrypt(ascon_state_t *state, uint8_t *plaintext, const uint8_t *ciphertext, size_t len);

/**
 * Core permutation function.
 */
void ascon_permutation(ascon_state_t *state, uint8_t rounds);

#endif // ASCON128_H
