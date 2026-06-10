// Import our library
use passman::crypto::{generate_password, encrypt_password, decrypt_password, derive_key, generate_salt};

fn main() {
    println!("🔐 PassMan - Secure Password Manager");
    println!("✅ Step 3 complete - Cryptography is working!\n");
    
    demo_password_generation();
    demo_encryption_decryption();
}

fn demo_password_generation() {
    println!("🔑 Password Generation:");
    
    let password = generate_password(20, true).unwrap();
    println!("  • Generated: {}", password);
    println!("  • Length: {}", password.len());
    println!();
}

fn demo_encryption_decryption() {
    println!("🔒 Encryption/Decryption Demo:");
    
    let master_password = "my_strong_master_password";
    let salt = generate_salt();
    let key = derive_key(master_password, &salt).unwrap();
    
    let original = "my_secret_password123!";
    println!("  • Original: {}", original);
    
    let (encrypted, nonce) = encrypt_password(original, &key).unwrap();
    println!("  • Encrypted: {} bytes", encrypted.len());
    
    let decrypted = decrypt_password(&encrypted, &key, &nonce).unwrap();
    println!("  • Decrypted: {}", decrypted);
    println!("  • Success: {}", original == decrypted);
}
