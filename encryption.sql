SET @key = 'YourSecretKeyHere';
SET @plaintext = 'Hello, world!';

SELECT HEX(AES_ENCRYPT(@plaintext, @key)) AS encrypted_message;