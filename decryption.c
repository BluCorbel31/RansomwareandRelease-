#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>

unsigned char *decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *decrypted_len) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    unsigned char *decrypted = (unsigned char *)malloc(ciphertext_len);
    AES_cbc_encrypt(ciphertext, decrypted, ciphertext_len, &aes_key, iv, AES_DECRYPT);

    int padding = (int)decrypted[ciphertext_len - 1];
    *decrypted_len = ciphertext_len - padding;
    return decrypted;
}

int main() {
    unsigned char ciphertext[] = {YourEncryptedMessageHere};
    int ciphertext_len = sizeof(ciphertext);

    unsigned char key[AES_BLOCK_SIZE] = {YourSecretKeyHere};
    unsigned char iv[AES_BLOCK_SIZE] = {YourInitializationVectorHere};

    int decrypted_len;
    unsigned char *decrypted = decrypt(ciphertext, ciphertext_len, key, iv, &decrypted_len);

    printf("Decrypted message: %s\n", decrypted);

    free(decrypted);
    return 0;
}