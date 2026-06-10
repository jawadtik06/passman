//! Integration tests for cryptography module

use passman::crypto::{
    DEFAULT_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, decrypt_password,
    derive_key, encrypt_password, generate_password, generate_salt, verify_password,
};

// Key Derivation Tests
#[test]
fn derive_key_creates_32_byte_key() {
    let salt = generate_salt();
    let key = derive_key("master_password", &salt).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn same_password_same_salt_produces_same_key() {
    let salt = generate_salt();
    let key1 = derive_key("password", &salt).unwrap();
    let key2 = derive_key("password", &salt).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn different_password_produces_different_key() {
    let salt = generate_salt();
    let key1 = derive_key("password1", &salt).unwrap();
    let key2 = derive_key("password2", &salt).unwrap();
    assert_ne!(key1, key2);
}

// Encryption/Decryption Tests
#[test]
fn encrypt_decrypt_roundtrip() {
    let salt = generate_salt();
    let key = derive_key("master", &salt).unwrap();
    let original = "my_secret_password";

    let (encrypted, nonce) = encrypt_password(original, &key).unwrap();
    let decrypted = decrypt_password(&encrypted, &key, &nonce).unwrap();

    assert_eq!(original, decrypted);
}

#[test]
fn encrypted_data_is_different_from_plaintext() {
    let salt = generate_salt();
    let key = derive_key("master", &salt).unwrap();
    let plaintext = "secret";

    let (encrypted, _) = encrypt_password(plaintext, &key).unwrap();
    assert_ne!(encrypted, plaintext.as_bytes());
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let salt1 = generate_salt();
    let salt2 = generate_salt();

    let key1 = derive_key("master1", &salt1).unwrap();
    let key2 = derive_key("master2", &salt2).unwrap();

    let (encrypted, nonce) = encrypt_password("secret", &key1).unwrap();
    let result = decrypt_password(&encrypted, &key2, &nonce);

    assert!(result.is_err());
}

// Password Hashing Tests
#[test]
fn hash_and_verify_correct_password() {
    let salt = generate_salt();
    let password = "master_password";

    let hash = passman::crypto::hash_password(password, &salt).unwrap();
    let is_valid = verify_password(password, &hash, &salt).unwrap();

    assert!(is_valid);
}

#[test]
fn hash_and_verify_wrong_password() {
    let salt = generate_salt();
    let hash = passman::crypto::hash_password("correct", &salt).unwrap();
    let is_valid = verify_password("wrong", &hash, &salt).unwrap();

    assert!(!is_valid);
}

// Password Generation Tests
#[test]
fn generate_password_default_length() {
    let password = generate_password(DEFAULT_PASSWORD_LENGTH, true).unwrap();
    assert_eq!(password.len(), DEFAULT_PASSWORD_LENGTH);
}

#[test]
fn generate_password_min_length() {
    let password = generate_password(MIN_PASSWORD_LENGTH, false).unwrap();
    assert_eq!(password.len(), MIN_PASSWORD_LENGTH);
}

#[test]
fn generate_password_max_length() {
    let password = generate_password(MAX_PASSWORD_LENGTH, false).unwrap();
    assert_eq!(password.len(), MAX_PASSWORD_LENGTH);
}

#[test]
fn generate_password_rejects_too_short() {
    assert!(generate_password(7, true).is_err());
}

#[test]
fn generate_password_rejects_too_long() {
    assert!(generate_password(65, true).is_err());
}

#[test]
fn generate_password_without_special_chars() {
    let password = generate_password(30, false).unwrap();
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn generate_password_with_special_chars() {
    let password = generate_password(30, true).unwrap();
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
    assert!(has_special);
}

#[test]
fn generate_password_creates_unique_passwords() {
    let pwd1 = generate_password(20, true).unwrap();
    let pwd2 = generate_password(20, true).unwrap();
    assert_ne!(pwd1, pwd2);
}

// Random Data Tests
#[test]
fn generate_salt_returns_16_bytes() {
    let salt = generate_salt();
    assert_eq!(salt.len(), 16);
}

#[test]
fn generate_salt_creates_unique_values() {
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    assert_ne!(salt1, salt2);
}

#[test]
fn generate_nonce_returns_12_bytes() {
    let nonce = passman::crypto::generate_nonce();
    assert_eq!(nonce.len(), 12);
}

// Real-World Scenarios
#[test]
fn full_workflow_master_password_to_decryption() {
    let master_password = "my_strong_master_password_123!";
    let salt = generate_salt();

    let key = derive_key(master_password, &salt).unwrap();
    let website_password = "user_actual_password_456!";
    let (encrypted, nonce) = encrypt_password(website_password, &key).unwrap();

    let derived_key_again = derive_key(master_password, &salt).unwrap();
    let decrypted = decrypt_password(&encrypted, &derived_key_again, &nonce).unwrap();

    assert_eq!(website_password, decrypted);
}

#[test]
fn wrong_master_password_fails_decryption() {
    let correct_master = "correct_password";
    let wrong_master = "wrong_password";
    let salt = generate_salt();

    let correct_key = derive_key(correct_master, &salt).unwrap();
    let (encrypted, nonce) = encrypt_password("secret", &correct_key).unwrap();

    let wrong_key = derive_key(wrong_master, &salt).unwrap();
    let result = decrypt_password(&encrypted, &wrong_key, &nonce);

    assert!(result.is_err());
}
