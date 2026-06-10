//! Cryptography module for PassMan
//!
//! Provides encryption, decryption, hashing, and key derivation functions.

use crate::errors::{PassManError, Result};
use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use rand::RngCore;

// Constants
pub const DEFAULT_PASSWORD_LENGTH: usize = 20;
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 64;
pub const SALT_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;

// Key Derivation
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    let argon2 = Argon2::default();
    let mut output = [0u8; KEY_LENGTH];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| PassManError::CryptoError(format!("Key derivation failed: {}", e)))?;

    Ok(output)
}

// Encryption/Decryption
pub fn encrypt_password(plaintext: &str, key: &[u8; KEY_LENGTH]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| PassManError::CryptoError(format!("Encryption failed: {}", e)))?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt_password(ciphertext: &[u8], key: &[u8; KEY_LENGTH], nonce: &[u8]) -> Result<String> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| PassManError::DecryptionError(format!("Decryption failed: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| PassManError::CryptoError(format!("Invalid UTF-8: {}", e)))
}

// Password Hashing
pub fn hash_password(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let argon2 = Argon2::default();
    let mut output = vec![0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| PassManError::CryptoError(format!("Hashing failed: {}", e)))?;

    Ok(output)
}

pub fn verify_password(password: &str, stored_hash: &[u8], salt: &[u8]) -> Result<bool> {
    let computed = hash_password(password, salt)?;
    Ok(computed == stored_hash)
}

// Password Generation
pub fn generate_password(length: usize, use_special: bool) -> Result<String> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
        return Err(PassManError::CryptoError(format!(
            "Password length must be between {} and {}",
            MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
        )));
    }

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    let charset: Vec<u8> = if use_special {
        CHARSET.iter().chain(SPECIAL.iter()).copied().collect()
    } else {
        CHARSET.to_vec()
    };

    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = (rng.next_u64() as usize) % charset.len();
            charset[idx] as char
        })
        .collect();

    Ok(password)
}

// Random Data Generation
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_returns_consistent_results() {
        let password = "test_master_password";
        let salt = generate_salt();

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), KEY_LENGTH);
    }

    #[test]
    fn derive_key_with_different_salt_returns_different_keys() {
        let password = "test_master_password";
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key1 = derive_key(password, &salt1).unwrap();
        let key2 = derive_key(password, &salt2).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_succeeds() {
        let plaintext = "my_secret_password";
        let salt = generate_salt();
        let key = derive_key("master", &salt).unwrap();

        let (ciphertext, nonce) = encrypt_password(plaintext, &key).unwrap();
        assert_ne!(ciphertext, plaintext.as_bytes());

        let decrypted = decrypt_password(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key1 = derive_key("master1", &salt1).unwrap();
        let key2 = derive_key("master2", &salt2).unwrap();

        let (ciphertext, nonce) = encrypt_password("secret", &key1).unwrap();
        let result = decrypt_password(&ciphertext, &key2, &nonce);

        assert!(result.is_err());
    }

    #[test]
    fn encrypt_uses_unique_nonce_each_time() {
        let salt = generate_salt();
        let key = derive_key("master", &salt).unwrap();

        let (ciphertext1, nonce1) = encrypt_password("secret", &key).unwrap();
        let (ciphertext2, nonce2) = encrypt_password("secret", &key).unwrap();

        assert_ne!(nonce1, nonce2);
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn hash_and_verify_correct_password() {
        let password = "master_password";
        let salt = generate_salt();

        let hash = hash_password(password, &salt).unwrap();
        assert_eq!(hash.len(), 32);

        assert!(verify_password(password, &hash, &salt).unwrap());
        assert!(!verify_password("wrong_password", &hash, &salt).unwrap());
    }

    #[test]
    fn hash_with_different_salt_produces_different_hashes() {
        let password = "password";
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let hash1 = hash_password(password, &salt1).unwrap();
        let hash2 = hash_password(password, &salt2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn generate_password_with_default_length() {
        let password = generate_password(DEFAULT_PASSWORD_LENGTH, true).unwrap();
        assert_eq!(password.len(), DEFAULT_PASSWORD_LENGTH);
    }

    #[test]
    fn generate_password_without_special_characters() {
        let password = generate_password(16, false).unwrap();
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_password_with_special_characters() {
        let password = generate_password(16, true).unwrap();
        assert_eq!(password.len(), 16);
        let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
        assert!(has_special);
    }

    #[test]
    fn generate_password_rejects_invalid_lengths() {
        assert!(generate_password(3, true).is_err());
        assert!(generate_password(7, true).is_err());
        assert!(generate_password(65, true).is_err());
    }

    #[test]
    fn generate_password_produces_unique_passwords() {
        let pwd1 = generate_password(20, true).unwrap();
        let pwd2 = generate_password(20, true).unwrap();
        assert_ne!(pwd1, pwd2);
    }

    #[test]
    fn generate_salt_returns_16_unique_bytes() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn generate_nonce_returns_12_unique_bytes() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert_eq!(nonce1.len(), NONCE_LENGTH);
        assert_eq!(nonce2.len(), NONCE_LENGTH);
        assert_ne!(nonce1, nonce2);
    }
}
