//! CLI module for PassMan - Professional Edition

use crate::crypto::{
    decrypt_password, derive_key, encrypt_password, generate_password, generate_salt,
};
use crate::db::Database;
use crate::errors::Result;
use crate::models::PasswordEntry;
use console::style;
use dialoguer::{Confirm, Input, Password, Select};

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

        println!("\n{}", style("PassMan - First Time Setup").bold().cyan());
        println!("{}", style("Create your master password").bold());
        println!(
            "{}",
            style("WARNING: If you lose this password, your data cannot be recovered!").red()
        );

        let password = Password::new()
            .with_prompt("Master password")
            .with_confirmation("Confirm master password", "Passwords do not match")
            .validate_with(|input: &String| {
                if input.len() >= 8 {
                    Ok(())
                } else {
                    Err("Password must be at least 8 characters")
                }
            })
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;

        let salt = generate_salt();
        let hash = crate::crypto::hash_password(&password, &salt)?;

        let vault_data = [salt.as_slice(), hash.as_slice()].concat();
        std::fs::write(VAULT_FILE, vault_data)?;

        println!("{}", style("[SUCCESS] Vault created successfully!").green());
        Ok(())
    }

    fn unlock_vault() -> Result<Vec<u8>> {
        let vault_data =
            std::fs::read(VAULT_FILE).map_err(|_| crate::errors::PassManError::VaultNotFound)?;

        let salt = &vault_data[0..16];
        let stored_hash = &vault_data[16..];

        println!("\n{}", style("PassMan - Unlock Vault").bold().cyan());

        for attempt in 1..=3 {
            let password = Password::new()
                .with_prompt("Master password")
                .interact()
                .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;

            if crate::crypto::verify_password(&password, stored_hash, salt)? {
                println!("{}", style("[SUCCESS] Vault unlocked!").green());
                let key = derive_key(&password, salt)?;
                return Ok(key.to_vec());
            }
            println!(
                "{}",
                style(format!("[ERROR] Wrong password (attempt {}/3)", attempt)).red()
            );
        }

        Err(crate::errors::PassManError::AuthenticationFailed)
    }

    pub fn run(&mut self) -> Result<()> {
        loop {
            println!("\n{}", style("PassMan - Main Menu").bold().cyan());
            println!(
                "{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
            );

            let choice = Select::new()
                .items(&[
                    "Add Password",
                    "List Passwords",
                    "Search Passwords",
                    "Generate Password",
                    "Delete Password",
                    "Exit",
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
                    println!("\n{}", style("Thank you for using PassMan").green());
                    println!("{}", style("Goodbye!").dim());
                    break;
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    fn add_password(&self) -> Result<()> {
        println!("\n{}", style("Add New Password").bold().cyan());
        println!(
            "{}",
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );

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

        let key_array: [u8; 32] = self.key.as_slice().try_into().map_err(|_| {
            crate::errors::PassManError::CryptoError("Invalid key length".to_string())
        })?;

        let (encrypted, nonce) = encrypt_password(&plain_password, &key_array)?;
        let entry = PasswordEntry::new(website, username, encrypted, nonce);
        self.db.insert(&entry)?;

        println!(
            "\n{}",
            style("[SUCCESS] Password saved successfully!").green()
        );
        Ok(())
    }

    fn list_passwords(&self) -> Result<()> {
        let entries = self.db.get_all()?;

        if entries.is_empty() {
            println!("\n{}", style("[INFO] No passwords saved yet.").yellow());
            return Ok(());
        }

        println!("\n{}", style("Password List").bold().cyan());
        println!(
            "{}",
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );

        let key_array: [u8; 32] = self.key.as_slice().try_into().map_err(|_| {
            crate::errors::PassManError::CryptoError("Invalid key length".to_string())
        })?;

        for (i, entry) in entries.iter().enumerate() {
            match decrypt_password(&entry.encrypted_password, &key_array, &entry.nonce) {
                Ok(decrypted) => {
                    let preview = format!(
                        "{}{}",
                        &decrypted[..decrypted.len().min(3)],
                        "*".repeat(decrypted.len().saturating_sub(3))
                    );
                    println!(
                        "  {}. {} - {}",
                        style(format!("{:3}", i + 1)).green().bold(),
                        style(&entry.website).cyan(),
                        style(&entry.username).white()
                    );
                    println!("     Password: {}", style(preview).dim());
                }
                Err(_) => {
                    println!(
                        "  {}. {} - {}",
                        style(format!("{:3}", i + 1)).green().bold(),
                        style(&entry.website).cyan(),
                        style(&entry.username).white()
                    );
                    println!("     Password: {}", style("[encrypted]").dim());
                }
            }
            if i < entries.len() - 1 {
                println!(
                    "{}",
                    style("  ─────────────────────────────────────────").dim()
                );
            }
        }

        println!(
            "\n{}",
            style(format!("Total: {} entries", entries.len())).dim()
        );

        if Confirm::new()
            .with_prompt("Reveal a password?")
            .default(false)
            .interact()
            .unwrap_or(false)
        {
            self.reveal_password()?;
        }

        Ok(())
    }

    fn reveal_password(&self) -> Result<()> {
        let entries = self.db.get_all()?;
        let items: Vec<String> = entries
            .iter()
            .map(|e| format!("{} - {}", e.website, e.username))
            .collect();

        let selection = Select::new()
            .with_prompt("Select entry")
            .items(&items)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;

        if let Some(entry) = entries.get(selection) {
            let key_array: [u8; 32] = self.key.as_slice().try_into().map_err(|_| {
                crate::errors::PassManError::CryptoError("Invalid key length".to_string())
            })?;

            let password = decrypt_password(&entry.encrypted_password, &key_array, &entry.nonce)?;
            println!("\n{}", style("Password:").bold());
            println!("{}", style(&password).yellow().bright());

            if Confirm::new()
                .with_prompt("Copy to clipboard?")
                .default(true)
                .interact()
                .unwrap_or(false)
            {
                let mut clipboard = arboard::Clipboard::new()
                    .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
                clipboard
                    .set_text(&password)
                    .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
                println!("{}", style("[INFO] Copied to clipboard").dim());
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
            println!(
                "\n{}",
                style("[INFO] No matching passwords found.").yellow()
            );
            return Ok(());
        }

        println!(
            "\n{}",
            style(format!("Search Results ({} entries)", entries.len()))
                .bold()
                .cyan()
        );
        println!(
            "{}",
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );

        let key_array: [u8; 32] = self.key.as_slice().try_into().map_err(|_| {
            crate::errors::PassManError::CryptoError("Invalid key length".to_string())
        })?;

        for (i, entry) in entries.iter().enumerate() {
            println!(
                "\n  [{}] {}",
                style(i + 1).green().bold(),
                style(&entry.website).cyan()
            );
            println!("      Username: {}", style(&entry.username).white());

            if Confirm::new()
                .with_prompt("Reveal password?")
                .default(false)
                .interact()
                .unwrap_or(false)
            {
                match decrypt_password(&entry.encrypted_password, &key_array, &entry.nonce) {
                    Ok(password) => println!("      Password: {}", style(password).yellow()),
                    Err(e) => println!("      {}", style(format!("Error: {}", e)).red()),
                }
            }
        }

        Ok(())
    }

    fn generate_password(&self) -> Result<()> {
        println!("\n{}", style("Password Generator").bold().cyan());
        println!(
            "{}",
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );

        let length: usize = Input::new()
            .with_prompt("Length (8-64)")
            .default(24)
            .validate_with(|l: &usize| {
                if (8..=64).contains(l) {
                    Ok(())
                } else {
                    Err("Length must be between 8 and 64")
                }
            })
            .interact_text()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;

        let use_special = Confirm::new()
            .with_prompt("Include special characters")
            .default(true)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;

        let password = generate_password(length, use_special)?;

        println!("\n{}", style("Generated Password:").bold());
        println!("{}", style(&password).yellow().bright());

        // Show password strength indicator
        let strength = if length >= 16 && use_special {
            "Strong"
        } else if length >= 12 {
            "Medium"
        } else {
            "Weak"
        };
        println!("{}", style(format!("Strength: {}", strength)).dim());

        if Confirm::new()
            .with_prompt("Copy to clipboard?")
            .default(true)
            .interact()
            .unwrap_or(false)
        {
            let mut clipboard = arboard::Clipboard::new()
                .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
            clipboard
                .set_text(&password)
                .map_err(|e| crate::errors::PassManError::ClipboardError(e.to_string()))?;
            println!("{}", style("[INFO] Copied to clipboard").dim());
        }

        Ok(())
    }

    fn delete_password(&self) -> Result<()> {
        let entries = self.db.get_all()?;

        if entries.is_empty() {
            println!("\n{}", style("[INFO] No passwords to delete.").yellow());
            return Ok(());
        }

        println!("\n{}", style("Delete Password").bold().cyan());
        println!(
            "{}",
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );

        let items: Vec<String> = entries
            .iter()
            .map(|e| format!("{} - {}", e.website, e.username))
            .collect();

        let selection = Select::new()
            .with_prompt("Select password to delete")
            .items(&items)
            .interact()
            .map_err(|e| crate::errors::PassManError::CryptoError(e.to_string()))?;

        if let Some(entry) = entries.get(selection) {
            if Confirm::new()
                .with_prompt(&format!(
                    "Delete '{}'? This action cannot be undone",
                    entry.website
                ))
                .default(false)
                .interact()
                .unwrap_or(false)
            {
                if let Some(id) = entry.id {
                    self.db.delete(id)?;
                    println!(
                        "\n{}",
                        style("[SUCCESS] Password deleted successfully!").green()
                    );
                }
            } else {
                println!("\n{}", style("[INFO] Deletion cancelled.").dim());
            }
        }
        Ok(())
    }
}
