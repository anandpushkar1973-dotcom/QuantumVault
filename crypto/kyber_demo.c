#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define IV_LEN 12
#define TAG_LEN 16

/* AES-256-GCM (Advanced Encryption Standard, Galois/Counter Mode) se encrypt */
static int aes_encrypt(const uint8_t *key, const uint8_t *pt, int pt_len,
                       uint8_t *iv, uint8_t *ct, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ct_len;
    RAND_bytes(iv, IV_LEN);  /* IV = Initialization Vector, har baar random */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

static int aes_decrypt(const uint8_t *key, const uint8_t *ct, int ct_len,
                       const uint8_t *iv, uint8_t *tag, uint8_t *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, pt_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    int ok = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ok > 0 ? pt_len + len : -1;  /* -1 matlab file se chhed-chhad hui */
}

int main(void) {
    /* Naye liboqs mein Kyber ka naam ML-KEM hai (standard version) */
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (kem == NULL) kem = OQS_KEM_new("Kyber768");
    if (kem == NULL) { printf("KEM (Key Encapsulation Mechanism) nahi mila\n"); return 1; }
    printf("Algorithm: %s\n", kem->method_name);

    uint8_t *public_key  = malloc(kem->length_public_key);
    uint8_t *secret_key  = malloc(kem->length_secret_key);
    uint8_t *ciphertext  = malloc(kem->length_ciphertext);
    uint8_t *secret_enc  = malloc(kem->length_shared_secret);
    uint8_t *secret_dec  = malloc(kem->length_shared_secret);

    /* 1. Keypair banao */
    OQS_KEM_keypair(kem, public_key, secret_key);
    /* 2. Encapsulation: public key se shared secret banao */
    OQS_KEM_encaps(kem, ciphertext, secret_enc, public_key);
    /* 3. Decapsulation: private key se wahi secret wapas nikalo */
    OQS_KEM_decaps(kem, secret_dec, ciphertext, secret_key);

    if (memcmp(secret_enc, secret_dec, kem->length_shared_secret) == 0)
        printf("Dono shared secret SAME hain. Kyber kaam kar raha hai!\n");
    else { printf("Secret match nahi hue\n"); return 1; }

    /* 4. Shared secret (32 bytes) ko AES key banake string encrypt karo */
    const char *msg = "Top secret: quantum se bhi safe!";
    int msg_len = strlen(msg);
    uint8_t iv[IV_LEN], tag[TAG_LEN], ct[256], pt[256];

    int ct_len = aes_encrypt(secret_enc, (const uint8_t *)msg, msg_len, iv, ct, tag);
    printf("Encrypted (hex): ");
    for (int i = 0; i < ct_len; i++) printf("%02x", ct[i]);
    printf("\n");

    int pt_len = aes_decrypt(secret_dec, ct, ct_len, iv, tag, pt);
    if (pt_len < 0) { printf("Decrypt fail\n"); return 1; }
    pt[pt_len] = '\0';
    printf("Decrypted: %s\n", pt);

    /* Memory saaf karo */
    OQS_MEM_cleanse(secret_key, kem->length_secret_key);
    OQS_MEM_cleanse(secret_enc, kem->length_shared_secret);
    OQS_MEM_cleanse(secret_dec, kem->length_shared_secret);
    free(public_key); free(secret_key); free(ciphertext);
    free(secret_enc); free(secret_dec);
    OQS_KEM_free(kem);
    return 0;
}