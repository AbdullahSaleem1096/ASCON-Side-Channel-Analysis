#include <stdio.h>
#include <string.h>
#include "ascon128.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t nonce[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t pt[] = "ASCON-128 Test Vector Implementation";
    size_t pt_len = strlen((char*)pt);
    uint8_t ad[] = "Cyber Security Lab 11";
    size_t ad_len = strlen((char*)ad);
    
    uint8_t ct[64];
    uint8_t tag[16];
    uint8_t decrypted[64];

    ascon_state_t state;

    printf("--- ASCON-128 Authenticated Encryption ---\n");
    print_hex("Key  ", key, 16);
    print_hex("Nonce", nonce, 16);
    print_hex("AD   ", ad, ad_len);
    print_hex("PT   ", pt, pt_len);

    // Encryption
    ascon128_init(&state, key, nonce);
    ascon128_ad(&state, ad, ad_len);
    ascon128_encrypt(&state, ct, pt, pt_len);
    ascon128_finalize(&state, key, tag);

    print_hex("CT   ", ct, pt_len);
    print_hex("Tag  ", tag, 16);

    // Decryption
    ascon128_init(&state, key, nonce);
    ascon128_ad(&state, ad, ad_len);
    ascon128_decrypt(&state, decrypted, ct, pt_len);
    
    print_hex("Decrypted", decrypted, pt_len);

    if (memcmp(pt, decrypted, pt_len) == 0) {
        printf("\nResult: Success (Decrypted text matches original)\n");
    } else {
        printf("\nResult: Failure (Decrypted text does NOT match original)\n");
    }

    return 0;
}
