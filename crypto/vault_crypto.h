#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define VAULT_KEY_LEN 32
#define VAULT_IV_LEN 12
#define VAULT_TAG_LEN 16
/* Encrypted data = IV + ciphertext + tag, isliye 28 bytes extra lagte hain */
#define VAULT_OVERHEAD (VAULT_IV_LEN + VAULT_TAG_LEN)

/* Encrypt karta hai. out ka size kam se kam in_len + VAULT_OVERHEAD hona chahiye.
   Success par out ki length return karta hai, fail par -1. */
int vault_encrypt(const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out);

/* Decrypt karta hai. out ka size kam se kam in_len - VAULT_OVERHEAD hona chahiye.
   Success par out ki length return karta hai, fail par -1. */
int vault_decrypt(const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out);

#endif