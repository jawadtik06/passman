//! CLI module for PassMan

use dialoguer::{Input, Password, Select, Confirm};
use console::style;
use crate::errors::Result;
use crate::models::PasswordEntry;
use crate::crypto::{derive_key, encrypt_password, decrypt_password, generate_password, generate_salt};
use crate::db::Database;

const VAULT_FILE: &str = "vault.key";
const DB_FILE: &str = "passwords.db";

pub struct Cli {
    db: Database,
    key: Vec<u8>,
}

impl Cli {
    pub fn new() -> Result<Self> {
        Self::init_vault()?;
        let key = Self::unlock_vault()?;
        let db = Database::new(DB_FILE)?;
        Ok(Self { db, key })
    }
    
    fn init_vault() -> Result<()> {
        if std::path::Path::new(VAULT_FILE).exists() {
            return Ok(());
        }
        
        println!("\n{}", style("🔐 First time setup").bold().cyan());
        println!("{}", style("Create your master password").bold());
        println!("{}", style("⚠️  WARNING: If you lose this password, your data is unrecoverable!").red());
        
        let password = Password::new()
            .with_prompt("Master password")
            .with_confirmation("Confirm master password", "Passwords don't match")
            .validate_with(|input: &String| {
                if input.len() >= 8 { Ok(()) } 
                else { Err("Password must be at least 8 characters") }
            })
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let salt = generate_salt();
        let hash = crate::crypto::hash_password(&password, &salt)?;
        
        let vault_data = [salt.as_slice(), hash.as_slice()].concat();
        std::fs::write(VAULT_FILE, vault_data)?;
        
        println!("{}", style("✓ Vault created successfully!").green());
        Ok(())
    }
    
    fn unlock_vault() -> Result<Vec<u8>> {
        let vault_data = std::fs::read(VAULT_FILE)
            .map_err(|_| crate::errors::PassManError::VaultNotFound)?;
        
        let salt = &vault_data[0..16];
        let stored_hash = &vault_data[16..];
        
        println!("\n{}", style("🔐 Unlock vault").bold().cyan());
        
        for attempt in 1..=3 {
            let password = Password::new()
                .with_prompt("Master password")
                .interact()
                .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
            
            if crate::crypto::verify_password(&password, stored_hash, salt)? {
                println!("{}", style("✓ Vault unlocked!").green());
                let key = derive_key(&password, salt)?;
                return Ok(key.to_vec());
            }
            println!("{}", style(format!("✗ Wrong password (attempt {}/3)", attempt)).red());
        }
        
        Err(crate::errors::PassManError::AuthenticationFailed)
    }
    
    pub fn run(&mut self) -> Result<()> {
        loop {
            println!("\n{}", style("📋 PassMan Menu").bold().green());
            let choice = Select::new()
                .items(&[
                    "➕ Add password",
                    "🔍 List passwords",
                    "🔎 Search passwords",
                    "🔑 Generate password",
                    "🗑️ Delete password",
                    "🚪 Exit",
                ])
                .default(0)
                .interact()
                .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
            
            match choice {
                0 => self.add_password()?,
                1 => self.list_passwords()?,
                2 => self.search_passwords()?,
                3 => self.generate_password()?,
                4 => self.delete_password()?,
                5 => {
                    println!("{}", style("\n✨ Goodbye! Stay secure! 👋").green());
                    break;
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
    
    fn add_password(&self) -> Result<()> {
        println!("\n{}", style("➕ Add new password").bold());
        
        let website: String = Input::new()
            .with_prompt("Website/Service")
            .interact_text()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let username: String = Input::new()
            .with_prompt("Username/Email")
            .interact_text()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let use_generated = Confirm::new()
            .with_prompt("Generate secure password?")
            .default(true)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let plain_password = if use_generated {
            let length: usize = Input::new()
                .with_prompt("Password length (default: 20)")
                .default(20)
                .interact_text()
                .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
            generate_password(length, true)?
        } else {
            Password::new()
                .with_prompt("Enter password")
                .interact()
                .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?
        };
        
        let key_array: [u8; 32] = self.key.as_slice().try_into()
            .map_err(|_| crate::errors::PassManError::CryptoError("Invalid key length".to_string()))?;
        
        let (encrypted, nonce) = encrypt_password(&plain_password, &key_array)?;
        let entry = PasswordEntry::new(website, username, encrypted, nonce);
        self.db.insert(&entry)?;
        
        println!("{}", style("✓ Password saved!").green());
        Ok(())
    }
    
    fn list_passwords(&self) -> Result<()> {
        let entries = self.db.get_all()?;
        
        if entries.is_empty() {
            println!("{}", style("\n📭 No passwords saved yet.").dim());
            return Ok(());
        }
        
        println!("\n{}", style("📋 Your passwords:").bold().underlined());
        
        let key_array: [u8; 32] = self.key.as_slice().try_into()
            .map_err(|_| crate::errors::PassManError::CryptoError("Invalid key length".to_string()))?;
        
        for (i, entry) in entries.iter().enumerate() {
            match decrypt_password(&entry.encrypted_password, &key_array, &entry.nonce) {
                Ok(decrypted) => {
                    let preview = format!("{}{}", &decrypted[..decrypted.len().min(3)], "*".repeat(decrypted.len().saturating_sub(3)));
                    println!("  {}. {} - {} [{}]", i + 1, style(&entry.website).cyan(), entry.username, style(preview).dim());
                }
                Err(_) => println!("  {}. {} - {} [{}]", i + 1, style(&entry.website).cyan(), entry.username, style("encrypted").dim()),
            }
        }
        
        if Confirm::new().with_prompt("Reveal a password?").default(false).interact().unwrap_or(false) {
            self.reveal_password()?;
        }
        
        Ok(())
    }
    
    fn reveal_password(&self) -> Result<()> {
        let entries = self.db.get_all()?;
        let items: Vec<String> = entries.iter()
            .map(|e| format!("{} - {}", e.website, e.username))
            .collect();
        
        let selection = Select::new()
            .with_prompt("Select entry")
            .items(&items)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        if let Some(entry) = entries.get(selection) {
            let key_array: [u8; 32] = self.key.as_slice().try_into()
                .map_err(|_| crate::errors::PassManError::CryptoError("Invalid key length".to_string()))?;
            
            let password = decrypt_password(&entry.encrypted_password, &key_array, &entry.nonce)?;
            println!("\n{}", style(&password).bold().yellow());
            
            if Confirm::new().with_prompt("Copy to clipboard?").default(true).interact().unwrap_or(false) {
                let mut clipboard = arboard::Clipboard::new()
                    .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
                clipboard.set_text(&password)
                    .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
                println!("{}", style("✓ Copied to clipboard!").dim());
            }
        }
        Ok(())
    }
    
    fn search_passwords(&self) -> Result<()> {
        let query: String = Input::new()
            .with_prompt("Search term")
            .interact_text()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let entries = self.db.search_by_website(&query)?;
        
        if entries.is_empty() {
            println!("{}", style("No matching passwords found.").dim());
            return Ok(());
        }
        
        println!("\n{}", style(format!("Found {} entries:", entries.len())).bold());
        
        let key_array: [u8; 32] = self.key.as_slice().try_into()
            .map_err(|_| crate::errors::PassManError::CryptoError("Invalid key length".to_string()))?;
        
        for entry in entries {
            println!("\n  {} {}", style("•").green(), style(&entry.website).cyan());
            println!("    Username: {}", entry.username);
            
            if Confirm::new().with_prompt("Reveal password?").default(false).interact().unwrap_or(false) {
                match decrypt_password(&entry.encrypted_password, &key_array, &entry.nonce) {
                    Ok(password) => println!("    Password: {}", style(password).yellow()),
                    Err(e) => println!("    {}", style(format!("Failed: {}", e)).red()),
                }
            }
        }
        Ok(())
    }
    
    fn generate_password(&self) -> Result<()> {
        println!("\n{}", style("🔑 Password Generator").bold());
        
        let length: usize = Input::new()
            .with_prompt("Length (8-64)")
            .default(24)
            .validate_with(|l: &usize| {
                if (8..=64).contains(l) { Ok(()) } 
                else { Err("Length must be between 8 and 64") }
            })
            .interact_text()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let use_special = Confirm::new()
            .with_prompt("Include special characters?")
            .default(true)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        let password = generate_password(length, use_special)?;
        println!("\n{}", style(&password).bold().yellow());
        
        if Confirm::new().with_prompt("Copy to clipboard?").default(true).interact().unwrap_or(false) {
            let mut clipboard = arboard::Clipboard::new()
                .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
            clipboard.set_text(&password)
                .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
            println!("{}", style("✓ Copied to clipboard!").dim());
        }
        Ok(())
    }
    
    fn delete_password(&self) -> Result<()> {
        let entries = self.db.get_all()?;
        
        if entries.is_empty() {
            println!("{}", style("No passwords to delete.").yellow());
            return Ok(());
        }
        
        let items: Vec<String> = entries.iter()
            .map(|e| format!("{} - {}", e.website, e.username))
            .collect();
        
        let selection = Select::new()
            .with_prompt("Select password to delete")
            .items(&items)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;
        
        if let Some(entry) = entries.get(selection) {
            if let Some(id) = entry.id {
                if Confirm::new()
                    .with_prompt(&format!("Delete {}? This cannot be undone!", entry.website))
                    .default(false)
                    .interact()
                    .unwrap_or(false)
                {
                    self.db.delete(id)?;
                    println!("{}", style("✓ Password deleted!").green());
                }
            }
        }
        Ok(())
    }
}
