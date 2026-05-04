#include "ascon128.h"
#include <string.h>

/* Helper macros for rotation */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* Helper functions for big-endian load/store */
static uint64_t load64(const uint8_t *src) {
    uint64_t w = 0;
    for (int i = 0; i < 8; i++) {
        w |= (uint64_t)src[i] << (8 * (7 - i));
    }
    return w;
}

static void store64(uint8_t *dst, uint64_t w) {
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)(w >> (8 * (7 - i)));
    }
}

/* Round constants for ASCON-128 */
static const uint8_t constants[] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

void ascon_permutation(ascon_state_t *state, uint8_t rounds) {
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;

    x0 = state->x[0];
    x1 = state->x[1];
    x2 = state->x[2];
    x3 = state->x[3];
    x4 = state->x[4];

    /* Start from the appropriate constant based on number of rounds */
    /* If rounds=12, start from constants[0]. If rounds=6, start from constants[6]. */
    int start_round = 12 - rounds;

    for (int i = start_round; i < 12; i++) {
        /* 1. Addition of Round Constant */
        x2 ^= constants[i];

        /* 2. Substitution Layer (S-box) */
        x0 ^= x4; x4 ^= x3; x2 ^= x1;
        t0 = ~x0 & x1; t1 = ~x1 & x2; t2 = ~x2 & x3; t3 = ~x3 & x4; t4 = ~x4 & x0;
        x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
        x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;

        /* 3. Linear Diffusion Layer */
        x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
        x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
        x2 ^= ROTR(x2, 1)  ^ ROTR(x2, 6);
        x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
        x4 ^= ROTR(x4, 7)  ^ ROTR(x4, 41);
    }

    state->x[0] = x0;
    state->x[1] = x1;
    state->x[2] = x2;
    state->x[3] = x3;
    state->x[4] = x4;
}

void ascon128_init(ascon_state_t *state, const uint8_t *key, const uint8_t *nonce) {
    /* ASCON-128 IV: k=128, r=64, a=12, b=6 */
    uint64_t iv = 0x80400c0600000000ULL;
    uint64_t k0 = load64(key);
    uint64_t k1 = load64(key + 8);
    uint64_t n0 = load64(nonce);
    uint64_t n1 = load64(nonce + 8);

    state->x[0] = iv;
    state->x[1] = k0;
    state->x[2] = k1;
    state->x[3] = n0;
    state->x[4] = n1;

    ascon_permutation(state, 12);

    state->x[3] ^= k0;
    state->x[4] ^= k1;
}

void ascon128_ad(ascon_state_t *state, const uint8_t *ad, size_t adlen) {
    if (adlen > 0) {
        size_t full_blocks = adlen / 8;
        for (size_t i = 0; i < full_blocks; i++) {
            state->x[0] ^= load64(ad + i * 8);
            ascon_permutation(state, 6);
        }

        /* Padding for partial block */
        uint8_t last_block[8] = {0};
        size_t remaining = adlen % 8;
        memcpy(last_block, ad + full_blocks * 8, remaining);
        last_block[remaining] = 0x80;
        
        state->x[0] ^= load64(last_block);
        ascon_permutation(state, 6);
    }

    /* Domain separation */
    state->x[4] ^= 1;
}

void ascon128_encrypt(ascon_state_t *state, uint8_t *ciphertext, const uint8_t *plaintext, size_t len) {
    size_t full_blocks = len / 8;
    for (size_t i = 0; i < full_blocks; i++) {
        state->x[0] ^= load64(plaintext + i * 8);
        store64(ciphertext + i * 8, state->x[0]);
        ascon_permutation(state, 6);
    }

    /* Padding for partial block */
    uint8_t last_block[8] = {0};
    size_t remaining = len % 8;
    memcpy(last_block, plaintext + full_blocks * 8, remaining);
    last_block[remaining] = 0x80;
    
    state->x[0] ^= load64(last_block);
    uint8_t final_ct[8];
    store64(final_ct, state->x[0]);
    memcpy(ciphertext + full_blocks * 8, final_ct, remaining);
}

void ascon128_finalize(ascon_state_t *state, const uint8_t *key, uint8_t *tag) {
    uint64_t k0 = load64(key);
    uint64_t k1 = load64(key + 8);

    state->x[1] ^= k0;
    state->x[2] ^= k1;

    ascon_permutation(state, 12);

    state->x[3] ^= k0;
    state->x[4] ^= k1;

    store64(tag, state->x[3]);
    store64(tag + 8, state->x[4]);
}

void ascon128_decrypt(ascon_state_t *state, uint8_t *plaintext, const uint8_t *ciphertext, size_t len) {
    size_t full_blocks = len / 8;
    for (size_t i = 0; i < full_blocks; i++) {
        uint64_t c = load64(ciphertext + i * 8);
        store64(plaintext + i * 8, state->x[0] ^ c);
        state->x[0] = c;
        ascon_permutation(state, 6);
    }

    /* Partial block decryption */
    size_t remaining = len % 8;
    uint8_t last_ct[8] = {0};
    memcpy(last_ct, ciphertext + full_blocks * 8, remaining);
    
    uint8_t s0_bytes[8];
    store64(s0_bytes, state->x[0]);
    for(size_t i=0; i<remaining; i++) {
        plaintext[full_blocks * 8 + i] = s0_bytes[i] ^ last_ct[i];
    }
    
    for(size_t i=0; i<remaining; i++) {
        s0_bytes[i] = last_ct[i];
    }
    s0_bytes[remaining] ^= 0x80;
    state->x[0] = load64(s0_bytes);
}
