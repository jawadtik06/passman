// Import our library
use passman::models::{PasswordEntry, SearchFilter};

fn main() {
    println!("🔐 PassMan - Secure Password Manager");
    println!("✅ Step 2 complete - Data models are working!\n");

    // Demonstrate creating a password entry
    demo_password_entry();

    // Demonstrate search filters
    demo_search_filter();
}

fn demo_password_entry() {
    println!("📝 Creating a new password entry:");

    let entry = PasswordEntry::new(
        "github.com".to_string(),
        "john_doe".to_string(),
        vec![0x01, 0x02, 0x03], // encrypted (would be real ciphertext)
        vec![0x04, 0x05, 0x06], // nonce
    );

    println!("  • Website: {}", entry.website);
    println!("  • Username: {}", entry.username);
    println!("  • Summary: {}", entry.summary());
    println!("  • Created: {}", entry.created_at);
    println!("  • Persisted: {}", entry.is_persisted());
    println!();
}

fn demo_search_filter() {
    println!("🔍 Using search filters:");

    let filter = SearchFilter::new()
        .with_website("github")
        .with_username("john");

    println!("  • Website query: {:?}", filter.website_query);
    println!("  • Username query: {:?}", filter.username_query);
    println!("  • Filter active: {}", filter.is_active());
}
