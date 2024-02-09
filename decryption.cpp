#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <sstream>
#include <iomanip>

std::string decrypt(const std::string& encrypted_message, const unsigned char* key) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    std::stringstream ss;
    for (size_t i = 0; i < encrypted_message.length(); i += 2) {
        unsigned int byte;
        ss << std::hex << encrypted_message.substr(i, 2);
        ss >> byte;
        encrypted_message[i / 2] = (char)byte;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    unsigned char decrypted[encrypted_message.length()];
    AES_cbc_encrypt((const unsigned char*)encrypted_message.c_str(), decrypted, encrypted_message.length(), &aes_key, iv, AES_DECRYPT);

    int padding = decrypted[encrypted_message.length() - 1];
    return std::string((char*)decrypted, encrypted_message.length() - padding);
}

int main() {
    std::string encrypted_message = "YourEncryptedMessageHere";
    unsigned char key[AES_BLOCK_SIZE] = { YourSecretKeyHere };

    std::string decrypted_message = decrypt(encrypted_message, key);
    std::cout << "Decrypted message: " << decrypted_message << std::endl;

    return 0;
}