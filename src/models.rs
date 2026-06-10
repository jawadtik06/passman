//! Data models for PassMan
//!
//! Defines the structures for storing password entries and vault configuration.

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Represents a single password entry in the vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordEntry {
    pub id: Option<i64>,
    pub website: String,
    pub username: String,
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
}

impl PasswordEntry {
    pub fn new(
        website: String,
        username: String,
        encrypted_password: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: None,
            website,
            username,
            encrypted_password,
            nonce,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now().to_rfc3339();
    }

    pub fn is_persisted(&self) -> bool {
        self.id.is_some()
    }

    pub fn summary(&self) -> String {
        format!("{} ({})", self.website, self.username)
    }

    pub fn matches_search(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        self.website.to_lowercase().contains(&query_lower)
            || self.username.to_lowercase().contains(&query_lower)
    }
}

/// Configuration for the vault encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub master_password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            master_password_hash: Vec::new(),
            salt: Vec::new(),
            memory_cost: 19456,
            time_cost: 2,
            parallelism: 1,
        }
    }
}

impl VaultConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_initialized(&self) -> bool {
        !self.master_password_hash.is_empty() && !self.salt.is_empty()
    }
}

/// Search filter for finding password entries
#[derive(Debug, Clone, Default)]
pub struct SearchFilter {
    pub website_query: Option<String>,
    pub username_query: Option<String>,
    pub created_after: Option<String>,
    pub updated_before: Option<String>,
}

impl SearchFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_website(mut self, query: &str) -> Self {
        self.website_query = Some(query.to_string());
        self
    }

    pub fn with_username(mut self, query: &str) -> Self {
        self.username_query = Some(query.to_string());
        self
    }

    pub fn is_active(&self) -> bool {
        self.website_query.is_some()
            || self.username_query.is_some()
            || self.created_after.is_some()
            || self.updated_before.is_some()
    }

    pub fn matches(&self, entry: &PasswordEntry) -> bool {
        if let Some(query) = &self.website_query {
            if !entry.website.to_lowercase().contains(&query.to_lowercase()) {
                return false;
            }
        }

        if let Some(query) = &self.username_query {
            if !entry
                .username
                .to_lowercase()
                .contains(&query.to_lowercase())
            {
                return false;
            }
        }

        if let Some(after) = &self.created_after {
            if entry.created_at < *after {
                return false;
            }
        }

        if let Some(before) = &self.updated_before {
            if entry.updated_at > *before {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_password_entry() {
        let entry = PasswordEntry::new(
            "example.com".to_string(),
            "user@example.com".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        assert_eq!(entry.website, "example.com");
        assert_eq!(entry.username, "user@example.com");
        assert_eq!(entry.encrypted_password, vec![1, 2, 3]);
        assert_eq!(entry.nonce, vec![4, 5, 6]);
        assert!(entry.id.is_none());
        assert!(!entry.created_at.is_empty());
        assert!(!entry.updated_at.is_empty());
        assert_eq!(entry.created_at, entry.updated_at);
    }

    #[test]
    fn touch_updates_timestamp() {
        let mut entry =
            PasswordEntry::new("test.com".to_string(), "test".to_string(), vec![1], vec![2]);

        let original_updated = entry.updated_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(10));
        entry.touch();

        assert_ne!(entry.updated_at, original_updated);
        assert_eq!(entry.created_at, original_updated);
    }

    #[test]
    fn is_persisted() {
        let mut entry =
            PasswordEntry::new("test.com".to_string(), "test".to_string(), vec![1], vec![2]);

        assert!(!entry.is_persisted());
        entry.id = Some(42);
        assert!(entry.is_persisted());
    }

    #[test]
    fn summary_format() {
        let entry = PasswordEntry::new(
            "github.com".to_string(),
            "john_doe".to_string(),
            vec![1],
            vec![2],
        );

        assert_eq!(entry.summary(), "github.com (john_doe)");
    }

    #[test]
    fn matches_search() {
        let entry = PasswordEntry::new(
            "github.com".to_string(),
            "john_doe".to_string(),
            vec![1],
            vec![2],
        );

        assert!(entry.matches_search("github"));
        assert!(entry.matches_search("john"));
        assert!(entry.matches_search("GITHUB"));
        assert!(!entry.matches_search("gitlab"));
        assert!(!entry.matches_search("jane"));
    }

    #[test]
    fn vault_config_default() {
        let config = VaultConfig::default();

        assert!(config.master_password_hash.is_empty());
        assert!(config.salt.is_empty());
        assert_eq!(config.memory_cost, 19456);
        assert_eq!(config.time_cost, 2);
        assert_eq!(config.parallelism, 1);
    }

    #[test]
    fn vault_config_new() {
        let config = VaultConfig::new();
        assert!(!config.is_initialized());
    }

    #[test]
    fn vault_config_is_initialized() {
        let mut config = VaultConfig::new();
        assert!(!config.is_initialized());

        config.master_password_hash = vec![1, 2, 3];
        config.salt = vec![4, 5, 6];
        assert!(config.is_initialized());
    }

    #[test]
    fn search_filter_builder() {
        let filter = SearchFilter::new()
            .with_website("github")
            .with_username("john");

        assert!(filter.is_active());
        assert_eq!(filter.website_query, Some("github".to_string()));
        assert_eq!(filter.username_query, Some("john".to_string()));
        assert!(filter.created_after.is_none());
        assert!(filter.updated_before.is_none());
    }

    #[test]
    fn empty_search_filter() {
        let filter = SearchFilter::new();
        assert!(!filter.is_active());
    }

    #[test]
    fn search_filter_website_only() {
        let filter = SearchFilter::new().with_website("github");
        assert_eq!(filter.website_query, Some("github".to_string()));
        assert!(filter.username_query.is_none());
        assert!(filter.is_active());
    }

    #[test]
    fn search_filter_username_only() {
        let filter = SearchFilter::new().with_username("john");
        assert_eq!(filter.username_query, Some("john".to_string()));
        assert!(filter.website_query.is_none());
        assert!(filter.is_active());
    }

    #[test]
    fn search_filter_matches() {
        let entry = PasswordEntry::new(
            "github.com".to_string(),
            "john_doe".to_string(),
            vec![1],
            vec![2],
        );

        let filter = SearchFilter::new().with_website("github");
        assert!(filter.matches(&entry));

        let filter = SearchFilter::new().with_username("john");
        assert!(filter.matches(&entry));

        let filter = SearchFilter::new().with_website("gitlab");
        assert!(!filter.matches(&entry));

        let filter = SearchFilter::new().with_username("jane");
        assert!(!filter.matches(&entry));
    }

    #[test]
    fn password_entry_clone() {
        let entry1 = PasswordEntry::new(
            "test.com".to_string(),
            "user".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        let entry2 = entry1.clone();

        assert_eq!(entry1.website, entry2.website);
        assert_eq!(entry1.username, entry2.username);
        assert_eq!(entry1.encrypted_password, entry2.encrypted_password);
        assert_eq!(entry1.nonce, entry2.nonce);
    }
}
