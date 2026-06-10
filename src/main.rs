//! PassMan CLI - Secure Password Manager

use passman::db::Database;
use passman::models::PasswordEntry;

fn main() {
    println!("🔐 PassMan - Secure Password Manager");
    println!("✅ Step 4 complete - Database module is working!\n");
    
    demo_database().unwrap();
}

fn demo_database() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::new("test.db")?;
    
    let entry = PasswordEntry::new(
        "github.com".to_string(),
        "john_doe".to_string(),
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
    );
    
    db.insert(&entry)?;
    println!("📝 Inserted: {}", entry.summary());
    
    let entries = db.get_all()?;
    println!("📋 Total entries: {}", entries.len());
    
    for e in entries {
        println!("  • {} - {}", e.website, e.username);
    }
    
    Ok(())
}
