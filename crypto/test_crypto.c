#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "vault_crypto.h"

static int passed = 0, failed = 0;

static void check(const char *name, int condition) {
    if (condition) { printf("[PASS] %s\n", name); passed++; }
    else           { printf("[FAIL] %s\n", name); failed++; }
}

int main(void) {
    uint8_t key[VAULT_KEY_LEN], wrong_key[VAULT_KEY_LEN];
    for (int i = 0; i < VAULT_KEY_LEN; i++) {
        key[i] = (uint8_t)i;
        wrong_key[i] = (uint8_t)(i + 1);
    }

    const char *msg = "Hello QuantumVault, ye ek test message hai!";
    size_t len = strlen(msg);
    uint8_t enc[256], enc2[256], tampered[256], dec[256];

    /* Test 1: encrypt hone par size sahi aana chahiye (message + 28 bytes) */
    int enc_len = vault_encrypt(key, (const uint8_t *)msg, len, enc);
    check("encrypt: size = message + overhead", enc_len == (int)(len + VAULT_OVERHEAD));

    /* Test 2: decrypt karke wahi message wapas aana chahiye */
    int dec_len = vault_decrypt(key, enc, (size_t)enc_len, dec);
    check("decrypt: wahi message wapas mila",
          dec_len == (int)len && memcmp(dec, msg, len) == 0);

    /* Test 3: encrypted data plaintext jaisa nahi dikhna chahiye */
    check("encrypted data plaintext se alag hai",
          memcmp(enc + VAULT_IV_LEN, msg, len) != 0);

    /* Test 4: do baar encrypt karne par alag output (kyunki IV random hai) */
    int enc2_len = vault_encrypt(key, (const uint8_t *)msg, len, enc2);
    check("same message do baar encrypt = alag output",
          enc2_len == enc_len && memcmp(enc, enc2, (size_t)enc_len) != 0);

    /* Test 5: galat key se decrypt fail hona chahiye */
    check("galat key se decrypt fail",
          vault_decrypt(wrong_key, enc, (size_t)enc_len, dec) == -1);

    /* Test 6: data mein chhed-chhad karne par decrypt fail hona chahiye */
    memcpy(tampered, enc, (size_t)enc_len);
    tampered[VAULT_IV_LEN + 2] ^= 0xFF;
    check("tampered data pakda gaya",
          vault_decrypt(key, tampered, (size_t)enc_len, dec) == -1);

    /* Test 7: khaali file (0 bytes) bhi encrypt/decrypt honi chahiye */
    uint8_t empty_enc[64], empty_dec[64];
    int e_len = vault_encrypt(key, (const uint8_t *)"", 0, empty_enc);
    int d_len = vault_decrypt(key, empty_enc, (size_t)e_len, empty_dec);
    check("khaali file kaam karti hai", e_len == VAULT_OVERHEAD && d_len == 0);

    /* Test 8: bahut chhota (adhura) data decrypt nahi hona chahiye */
    check("adhura data reject hua", vault_decrypt(key, enc, 5, dec) == -1);

    printf("\nResult: %d pass, %d fail\n", passed, failed);
    return failed ? 1 : 0;
}