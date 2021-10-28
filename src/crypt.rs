use rand_core::OsRng;
use x25519_dalek::{SharedSecret};
use openssl::aes::{AesKey, aes_ige};
use openssl::symm::Mode;


pub type SecretKey = x25519_dalek::StaticSecret;
pub type PublicKey = x25519_dalek::PublicKey;

pub fn generate_keys() -> (SecretKey, PublicKey) {
    let secret = SecretKey::new(OsRng);
    let public = PublicKey::from(&secret);

    (secret, public)
}

pub fn generate_shared_secret(your_secret: &SecretKey, their_public_key: &PublicKey) -> SharedSecret {
    your_secret.diffie_hellman(&their_public_key)
}

fn pad_data(data: &mut Vec<u8>) {
    let len = data.len();
    let pad_amount = if len % 16 == 0 {
        0
    } else {
        16 - (len % 16)
    };
    data.resize(len + pad_amount, 0);
}

pub fn encrypt(data: &mut Vec<u8>, shared_secret: &SharedSecret) -> Vec<u8> {
    let mut iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
    let key = AesKey::new_encrypt(shared_secret.as_bytes()).unwrap();
    pad_data(data);
    let mut encrypted = data.clone();
    aes_ige(data, &mut encrypted, &key, &mut iv, Mode::Encrypt);
    encrypted
}

pub fn decrypt(data: &mut Vec<u8>, shared_secret: &SharedSecret) -> Vec<u8> {
    let mut iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
    let key = AesKey::new_decrypt(shared_secret.as_bytes()).unwrap();
    pad_data(data);
    let mut decrypted = data.clone();
    aes_ige(data, &mut decrypted, &key, &mut iv, Mode::Decrypt);
    decrypted
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn reciprocal() {
        let mut data = vec![1 as u8, 2 as u8, 3 as u8];
        pad_data(&mut data);
        let (your_secret, _) = generate_keys();
        let (_, their_public_key) = generate_keys();
        let shared_secret = generate_shared_secret(&your_secret, &their_public_key);
        let old_data = data.clone();
        
        let mut encrypted = encrypt(&mut data, &shared_secret);
        let decrypted = decrypt(&mut encrypted, &shared_secret);

        assert_eq!(old_data, decrypted);
    }
}
