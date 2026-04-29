use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

type AesBlock = aes::cipher::generic_array::GenericArray<u8, aes::cipher::typenum::U16>;

pub fn hex_to_key(hex_str: &str) -> Result<[u8; 32], String> {
    let cleaned: String = hex_str
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.len() != 64 {
        return Err(format!(
            "Key must be 64 hex characters (got {})",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(&cleaned).map_err(|e| format!("Invalid hex key: {}", e))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// AES-256-CFB decrypt.
/// CFB-128: encrypt IV to get keystream, XOR with ciphertext, feedback = ciphertext (input).
/// Input `data` is ciphertext, overwritten with plaintext.
pub fn aes256_cfb_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new_from_slice(key).expect("AES256 key must be 32 bytes");
    let mut feedback = AesBlock::clone_from_slice(iv);

    let len = data.len();
    let blocks = len / 16;
    let remainder = len % 16;

    for i in 0..blocks {
        let start = i * 16;
        cipher.encrypt_block(&mut feedback);
        // Save ciphertext for next feedback BEFORE overwriting with plaintext
        let next_feedback = AesBlock::clone_from_slice(&data[start..start + 16]);
        for j in 0..16 {
            data[start + j] ^= feedback[j];
        }
        feedback = next_feedback;
    }

    if remainder > 0 {
        let start = blocks * 16;
        cipher.encrypt_block(&mut feedback);
        for j in 0..remainder {
            data[start + j] ^= feedback[j];
        }
    }
}

/// AES-256-CFB encrypt.
/// CFB-128: encrypt IV to get keystream, XOR with plaintext, feedback = ciphertext (output).
/// Input `data` is plaintext, overwritten with ciphertext.
#[allow(dead_code)]
pub fn aes256_cfb_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new_from_slice(key).expect("AES256 key must be 32 bytes");
    let mut feedback = AesBlock::clone_from_slice(iv);

    let len = data.len();
    let blocks = len / 16;
    let remainder = len % 16;

    for i in 0..blocks {
        let start = i * 16;
        cipher.encrypt_block(&mut feedback);
        for j in 0..16 {
            data[start + j] ^= feedback[j];
        }
        // Feedback = ciphertext (output, after XOR)
        feedback = AesBlock::clone_from_slice(&data[start..start + 16]);
    }

    if remainder > 0 {
        let start = blocks * 16;
        cipher.encrypt_block(&mut feedback);
        for j in 0..remainder {
            data[start + j] ^= feedback[j];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfb_roundtrip() {
        let key = [0xabu8; 32];
        let iv = [0x42u8; 16];
        let plaintext = b"Hello, World! This is a test of AES-256-CFB mode.";

        let pad = (16 - plaintext.len() % 16) % 16;
        let mut buf = plaintext.to_vec();
        buf.resize(plaintext.len() + pad, 0);

        // Encrypt
        let mut ciphertext = buf.clone();
        aes256_cfb_encrypt(&key, &iv, &mut ciphertext);

        // Decrypt
        let mut decrypted = ciphertext.clone();
        aes256_cfb_decrypt(&key, &iv, &mut decrypted);

        assert_eq!(&decrypted, &buf);
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }
}
