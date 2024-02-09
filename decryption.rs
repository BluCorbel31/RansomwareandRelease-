use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::convert::TryInto;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn decrypt_message(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &encrypted[..16];
    let ciphertext = &encrypted[16..];

    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    let decrypted = cipher.decrypt_vec(ciphertext).unwrap();

    decrypted
}

fn main() {
    let encrypted_message = b"YourEncryptedMessageHere";
    let key: [u8; 16] = [YourSecretKeyHere];
    let decrypted_message = decrypt_message(encrypted_message, &key);
    println!("Decrypted message: {:?}", decrypted_message);
}