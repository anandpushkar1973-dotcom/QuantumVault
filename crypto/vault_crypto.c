#include "vault_crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int vault_encrypt(const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    uint8_t *iv = out;                          /* pehle 12 bytes: IV */
    uint8_t *ct = out + VAULT_IV_LEN;           /* phir ciphertext */
    int len = 0, ct_len = 0;

    if (RAND_bytes(iv, VAULT_IV_LEN) != 1) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ct, &len, in, (int)in_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len += len;

    /* Aakhir ke 16 bytes: tag (chhed-chhad pakadne ke liye) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VAULT_TAG_LEN, ct + ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return VAULT_IV_LEN + ct_len + VAULT_TAG_LEN;
}

int vault_decrypt(const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (in_len < VAULT_OVERHEAD) return -1;

    const uint8_t *iv = in;
    const uint8_t *ct = in + VAULT_IV_LEN;
    size_t ct_len = in_len - VAULT_OVERHEAD;
    uint8_t tag[VAULT_TAG_LEN];
    int len = 0, pt_len = 0;

    memcpy(tag, in + VAULT_IV_LEN + ct_len, VAULT_TAG_LEN);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VAULT_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Agar tag match nahi hua, matlab data badla gaya hai */
    if (EVP_DecryptFinal_ex(ctx, out + pt_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return pt_len;
}