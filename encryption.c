#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

unsigned char *encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, int *encrypted_len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    int padding = AES_BLOCK_SIZE - (plaintext_len % AES_BLOCK_SIZE);
    int total_len = plaintext_len + padding;

    unsigned char *input = (unsigned char *)malloc(total_len);
    memcpy(input, plaintext, plaintext_len);
    memset(input + plaintext_len, (unsigned char)padding, padding);

    unsigned char *encrypted = (unsigned char *)malloc(total_len);
    AES_cbc_encrypt(input, encrypted, total_len, &aes_key, iv, AES_ENCRYPT);

    *encrypted_len = total_len;
    free(input);
    return encrypted;
}

int main() {
    unsigned char *plaintext = (unsigned char *)"Hello, world!";
    int plaintext_len = strlen((char *)plaintext);

    unsigned char key[AES_BLOCK_SIZE];
    RAND_bytes(key, AES_BLOCK_SIZE);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    int encrypted_len;
    unsigned char *encrypted = encrypt(plaintext, plaintext_len, key, iv, &encrypted_len);

    printf("Encrypted message: ");
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    free(encrypted);
    return 0;
}