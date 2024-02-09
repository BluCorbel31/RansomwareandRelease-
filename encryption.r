library(openssl)

encrypt_message <- function(plaintext, key) {
  encrypted <- openssl_encrypt(plaintext, key, "AES-128-CBC", iv = NULL, padding = "PKCS5")
  return(encrypted)
}

plaintext <- "Hello, world!"
key <- charToRaw("YourSecretKeyHere")
encrypted_message <- encrypt_message(plaintext, key)
cat("Encrypted message:", encrypted_message, "\n")