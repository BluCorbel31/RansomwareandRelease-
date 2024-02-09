SET @key = 'YourSecretKeyHere';
SET @encrypted_message = UNHEX('YourEncryptedMessageHere');

SELECT AES_DECRYPT(@encrypted_message, @key) AS decrypted_message;