//! Integration tests for database module

use passman::db::Database;
use passman::models::PasswordEntry;
use rusqlite::Connection;

fn setup_db() -> Database {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute(
        "CREATE TABLE passwords (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    ).unwrap();
    conn.execute("CREATE INDEX idx_website ON passwords(website)", []).unwrap();
    conn.execute("CREATE INDEX idx_username ON passwords(username)", []).unwrap();
    Database::from_connection(conn)
}

fn test_entry() -> PasswordEntry {
    PasswordEntry::new(
        "example.com".to_string(),
        "alice".to_string(),
        vec![1, 2, 3],
        vec![4, 5, 6],
    )
}

#[test]
fn database_initialization() {
    let db = setup_db();
    assert_eq!(db.count().unwrap(), 0);
}

#[test]
fn insert_and_retrieve() {
    let db = setup_db();
    db.insert(&test_entry()).unwrap();
    let entries = db.get_all().unwrap();
    
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].website, "example.com");
    assert_eq!(entries[0].username, "alice");
}

#[test]
fn search_by_website() {
    let db = setup_db();
    db.insert(&test_entry()).unwrap();
    assert_eq!(db.search_by_website("example").unwrap().len(), 1);
    assert_eq!(db.search_by_website("unknown").unwrap().len(), 0);
}

#[test]
fn search_by_username() {
    let db = setup_db();
    db.insert(&test_entry()).unwrap();
    assert_eq!(db.search_by_username("alice").unwrap().len(), 1);
    assert_eq!(db.search_by_username("unknown").unwrap().len(), 0);
}

#[test]
fn update_password() {
    let db = setup_db();
    db.insert(&test_entry()).unwrap();
    let id = db.get_all().unwrap()[0].id.unwrap();
    
    db.update(id, vec![9, 9, 9], vec![8, 8, 8]).unwrap();
    let updated = db.get_by_id(id).unwrap().unwrap();
    assert_eq!(updated.encrypted_password, vec![9, 9, 9]);
    assert_eq!(updated.nonce, vec![8, 8, 8]);
}

#[test]
fn delete_entry() {
    let db = setup_db();
    db.insert(&test_entry()).unwrap();
    let id = db.get_all().unwrap()[0].id.unwrap();
    db.delete(id).unwrap();
    assert_eq!(db.count().unwrap(), 0);
}

#[test]
fn count_tracking() {
    let db = setup_db();
    assert_eq!(db.count().unwrap(), 0);
    db.insert(&test_entry()).unwrap();
    assert_eq!(db.count().unwrap(), 1);
    db.insert(&test_entry()).unwrap();
    assert_eq!(db.count().unwrap(), 2);
}

#[test]
fn multiple_entries() {
    let db = setup_db();
    
    let entry1 = PasswordEntry::new("github.com".to_string(), "user1".to_string(), vec![1, 2, 3], vec![4, 5, 6]);
    let entry2 = PasswordEntry::new("gitlab.com".to_string(), "user2".to_string(), vec![7, 8, 9], vec![10, 11, 12]);
    
    db.insert(&entry1).unwrap();
    db.insert(&entry2).unwrap();
    assert_eq!(db.get_all().unwrap().len(), 2);
}

#[test]
fn get_nonexistent_id() {
    let db = setup_db();
    assert!(db.get_by_id(999).unwrap().is_none());
}
