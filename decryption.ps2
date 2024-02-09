$encrypted = "YourEncryptedMessageHere"
$key = "YourSecretKeyHere"
$plaintext = ConvertTo-SecureString -String $encrypted -Key $key | ConvertFrom-SecureString
Write-Output "Decrypted message: $plaintext"