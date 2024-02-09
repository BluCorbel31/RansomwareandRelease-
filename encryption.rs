use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand_core::OsRng;
use rand_core::RngCore;
use std::convert::TryInto;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn encrypt_message(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut iv);

    let cipher = Aes128Cbc::new_from_slices(key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext);

    let mut encrypted = iv.to_vec();
    encrypted.extend_from_slice(&ciphertext);

    encrypted
}

fn main() {
    let plaintext = b"Hello, world!";
    let key: [u8; 16] = [YourSecretKeyHere];
    let encrypted_message = encrypt_message(plaintext, &key);
    println!("Encrypted message: {:?}", encrypted_message);
}