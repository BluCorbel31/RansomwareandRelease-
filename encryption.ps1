$plaintext = "Hello, world!"
$key = "YourSecretKeyHere"
$encrypted = ConvertTo-SecureString -String $plaintext -AsPlainText -Force | ConvertFrom-SecureString -Key $key
Write-Output "Encrypted message: $encrypted"