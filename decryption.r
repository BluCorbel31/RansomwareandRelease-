library(openssl)

decrypt_message <- function(encrypted_text, key) {
  decrypted <- openssl_decrypt(encrypted_text, key, "AES-128-CBC", iv = NULL, padding = "PKCS5")
  return(decrypted)
}

encrypted_text <- "YourEncryptedMessageHere"
key <- charToRaw("YourSecretKeyHere")
decrypted_message <- decrypt_message(encrypted_text, key)
cat("Decrypted message:", decrypted_message, "\n")