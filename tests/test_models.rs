//! Integration tests for PassMan data models

use passman::models::{PasswordEntry, SearchFilter, VaultConfig};

// PasswordEntry Tests
#[test]
fn create_password_entry() {
    let entry = PasswordEntry::new(
        "example.com".to_string(),
        "alice@example.com".to_string(),
        vec![0x01, 0x02, 0x03],
        vec![0x04, 0x05, 0x06],
    );

    assert_eq!(entry.website, "example.com");
    assert_eq!(entry.username, "alice@example.com");
    assert_eq!(entry.encrypted_password, vec![0x01, 0x02, 0x03]);
    assert_eq!(entry.nonce, vec![0x04, 0x05, 0x06]);
    assert!(entry.id.is_none());
    assert!(!entry.created_at.is_empty());
    assert!(!entry.updated_at.is_empty());
}

#[test]
fn touch_updates_timestamp() {
    let mut entry = PasswordEntry::new(
        "test.com".to_string(),
        "user".to_string(),
        vec![1],
        vec![2],
    );

    let old_updated = entry.updated_at.clone();
    std::thread::sleep(std::time::Duration::from_millis(10));
    entry.touch();

    assert_ne!(entry.updated_at, old_updated);
    assert_eq!(entry.created_at, old_updated);
}

#[test]
fn is_persisted() {
    let mut entry = PasswordEntry::new(
        "test.com".to_string(),
        "user".to_string(),
        vec![1],
        vec![2],
    );

    assert!(!entry.is_persisted());
    entry.id = Some(1);
    assert!(entry.is_persisted());
}

#[test]
fn summary_format() {
    let entry = PasswordEntry::new(
        "github.com".to_string(),
        "john".to_string(),
        vec![1],
        vec![2],
    );

    assert_eq!(entry.summary(), "github.com (john)");
}

// SearchFilter Tests
#[test]
fn search_filter_builder() {
    let filter = SearchFilter::new()
        .with_website("github")
        .with_username("john");

    assert_eq!(filter.website_query, Some("github".to_string()));
    assert_eq!(filter.username_query, Some("john".to_string()));
    assert!(filter.is_active());
}

#[test]
fn empty_search_filter() {
    let filter = SearchFilter::new();
    assert!(!filter.is_active());
}

#[test]
fn search_filter_with_only_website() {
    let filter = SearchFilter::new().with_website("github");
    assert_eq!(filter.website_query, Some("github".to_string()));
    assert!(filter.username_query.is_none());
    assert!(filter.is_active());
}

#[test]
fn search_filter_with_only_username() {
    let filter = SearchFilter::new().with_username("john");
    assert_eq!(filter.username_query, Some("john".to_string()));
    assert!(filter.website_query.is_none());
    assert!(filter.is_active());
}

// VaultConfig Tests
#[test]
fn vault_config_default() {
    let config = VaultConfig::default();

    assert_eq!(config.memory_cost, 19456);
    assert_eq!(config.time_cost, 2);
    assert_eq!(config.parallelism, 1);
    assert!(config.master_password_hash.is_empty());
    assert!(config.salt.is_empty());
}

#[test]
fn vault_config_can_be_modified() {
    let mut config = VaultConfig::default();

    config.memory_cost = 4096;
    config.time_cost = 3;
    config.parallelism = 2;

    assert_eq!(config.memory_cost, 4096);
    assert_eq!(config.time_cost, 3);
    assert_eq!(config.parallelism, 2);
}

// Edge Cases
#[test]
fn password_entry_with_empty_fields() {
    let entry = PasswordEntry::new("".to_string(), "".to_string(), vec![], vec![]);

    assert_eq!(entry.website, "");
    assert_eq!(entry.username, "");
    assert!(entry.encrypted_password.is_empty());
    assert!(entry.nonce.is_empty());
    assert!(entry.id.is_none());
}

#[test]
fn password_entry_with_long_fields() {
    let long_website = "a".repeat(1000);
    let long_username = "b".repeat(1000);

    let entry = PasswordEntry::new(
        long_website.clone(),
        long_username.clone(),
        vec![1, 2, 3],
        vec![4, 5, 6],
    );

    assert_eq!(entry.website, long_website);
    assert_eq!(entry.username, long_username);
}
