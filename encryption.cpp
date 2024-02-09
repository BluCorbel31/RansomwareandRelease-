#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iomanip>

std::string encrypt(const std::string& plaintext, const unsigned char* key) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    int padding = AES_BLOCK_SIZE - (plaintext.length() % AES_BLOCK_SIZE);
    std::string padded_plaintext = plaintext + std::string(padding, (char)padding);

    unsigned char ciphertext[padded_plaintext.length()];
    AES_cbc_encrypt((const unsigned char*)padded_plaintext.c_str(), ciphertext, padded_plaintext.length(), &aes_key, iv, AES_ENCRYPT);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < padded_plaintext.length(); ++i) {
        ss << std::setw(2) << (int)ciphertext[i];
    }
    return ss.str();
}

int main() {
    std::string plaintext = "Hello, world!";
    unsigned char key[AES_BLOCK_SIZE];
    RAND_bytes(key, AES_BLOCK_SIZE);

    std::string encrypted_message = encrypt(plaintext, key);
    std::cout << "Encrypted message: " << encrypted_message << std::endl;

    return 0;
}