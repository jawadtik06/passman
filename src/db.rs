//! Database module for PassMan

use crate::errors::{PassManError, Result};
use crate::models::PasswordEntry;
use rusqlite::{Connection, params};

#[derive(Debug)]
pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_website ON passwords(website)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_username ON passwords(username)",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn from_connection(conn: Connection) -> Self {
        Self { conn }
    }

    pub fn insert(&self, entry: &PasswordEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO passwords (website, username, encrypted_password, nonce, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.website, entry.username,
                entry.encrypted_password, entry.nonce,
                entry.created_at, entry.updated_at,
            ],
        )?;
        Ok(())
    }

    fn map_rows(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<PasswordEntry>> {
        let mut stmt = self.conn.prepare(sql)?;
        let entries = stmt.query_map(params, |row| {
            Ok(PasswordEntry {
                id: row.get(0)?,
                website: row.get(1)?,
                username: row.get(2)?,
                encrypted_password: row.get(3)?,
                nonce: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;

        entries
            .map(|e| e.map_err(|err| PassManError::DatabaseError(err.to_string())))
            .collect()
    }

    pub fn get_all(&self) -> Result<Vec<PasswordEntry>> {
        self.map_rows(
            "SELECT id, website, username, encrypted_password, nonce, created_at, updated_at 
             FROM passwords ORDER BY website",
            &[],
        )
    }

    pub fn get_by_id(&self, id: i64) -> Result<Option<PasswordEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, website, username, encrypted_password, nonce, created_at, updated_at 
             FROM passwords WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(PasswordEntry {
                id: row.get(0)?,
                website: row.get(1)?,
                username: row.get(2)?,
                encrypted_password: row.get(3)?,
                nonce: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;

        rows.next()
            .transpose()
            .map_err(|e| PassManError::DatabaseError(e.to_string()))
    }

    pub fn search_by_website(&self, query: &str) -> Result<Vec<PasswordEntry>> {
        self.map_rows(
            "SELECT id, website, username, encrypted_password, nonce, created_at, updated_at 
             FROM passwords WHERE website LIKE ?1 ORDER BY website",
            &[&format!("%{}%", query)],
        )
    }

    pub fn search_by_username(&self, query: &str) -> Result<Vec<PasswordEntry>> {
        self.map_rows(
            "SELECT id, website, username, encrypted_password, nonce, created_at, updated_at 
             FROM passwords WHERE username LIKE ?1 ORDER BY website",
            &[&format!("%{}%", query)],
        )
    }

    pub fn update(&self, id: i64, encrypted_password: Vec<u8>, nonce: Vec<u8>) -> Result<()> {
        use chrono::Utc;
        self.conn.execute(
            "UPDATE passwords SET encrypted_password = ?1, nonce = ?2, updated_at = ?3 WHERE id = ?4",
            params![encrypted_password, nonce, Utc::now().to_rfc3339(), id],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM passwords WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM passwords", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    pub fn clear_all(&self) -> Result<()> {
        self.conn.execute("DELETE FROM passwords", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        )
        .unwrap();
        conn.execute("CREATE INDEX idx_website ON passwords(website)", [])
            .unwrap();
        conn.execute("CREATE INDEX idx_username ON passwords(username)", [])
            .unwrap();
        Database::from_connection(conn)
    }

    fn test_entry() -> PasswordEntry {
        PasswordEntry::new(
            "github.com".to_string(),
            "testuser".to_string(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
        )
    }

    #[test]
    fn insert_and_get_all() {
        let db = setup_db();
        db.insert(&test_entry()).unwrap();
        let entries = db.get_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].website, "github.com");
    }

    #[test]
    fn get_by_id() {
        let db = setup_db();
        db.insert(&test_entry()).unwrap();
        let id = db.get_all().unwrap()[0].id.unwrap();
        assert!(db.get_by_id(id).unwrap().is_some());
    }

    #[test]
    fn search_by_website() {
        let db = setup_db();
        db.insert(&test_entry()).unwrap();
        assert_eq!(db.search_by_website("github").unwrap().len(), 1);
        assert_eq!(db.search_by_website("gitlab").unwrap().len(), 0);
    }

    #[test]
    fn search_by_username() {
        let db = setup_db();
        db.insert(&test_entry()).unwrap();
        assert_eq!(db.search_by_username("testuser").unwrap().len(), 1);
        assert_eq!(db.search_by_username("unknown").unwrap().len(), 0);
    }

    #[test]
    fn update_entry() {
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
        assert_eq!(db.get_all().unwrap().len(), 0);
    }

    #[test]
    fn count_entries() {
        let db = setup_db();
        assert_eq!(db.count().unwrap(), 0);
        db.insert(&test_entry()).unwrap();
        assert_eq!(db.count().unwrap(), 1);
        db.insert(&test_entry()).unwrap();
        assert_eq!(db.count().unwrap(), 2);
    }
}
