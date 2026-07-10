//! The offline-first local data layer.
//!
//! Survival-critical paths run air-gapped, so the cache is the *default* source
//! of truth, not a performance nicety: numintel serves from here with no network,
//! and an online lookup (when the operator opts into that mode) write-throughs to
//! here so the next offline query hits. The trait keeps the shell independent of
//! the backend; the rusqlite impl is the concrete offline store. Later layers
//! (signal fingerprints, switch profiles) add tables behind the same trait.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

/// A key/value intelligence cache. The abstraction the shell and plugins depend
/// on; `rusqlite` is one implementation.
pub trait IntelStore: Send + Sync {
    /// Fetch a cached value under `(namespace, key)`, if present.
    ///
    /// # Errors
    /// Returns [`StoreError`] on a backend failure (not on a cache miss — a miss
    /// is `Ok(None)`).
    fn get(&self, namespace: &str, key: &str) -> Result<Option<String>, StoreError>;

    /// Insert or replace the value under `(namespace, key)`.
    ///
    /// # Errors
    /// Returns [`StoreError`] on a backend failure.
    fn put(&self, namespace: &str, key: &str, value: &str) -> Result<(), StoreError>;
}

/// A data-layer failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The backend (sqlite) reported an error.
    #[error("store backend: {0}")]
    Backend(String),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Backend(e.to_string())
    }
}

/// A sqlite-backed [`IntelStore`]. Uses the `bundled` sqlite so the binary needs
/// no system libsqlite — it stays a self-contained static artifact on the SBC.
///
/// The connection is behind a `Mutex`: `rusqlite::Connection` is `Send` but not
/// `Sync` (its statement cache is a `RefCell`), and the store is shared across
/// the shell as `Arc<dyn IntelStore>`. A mutex is the right tool at Sprint-1
/// query volume; a connection pool is a later optimization if contention shows.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (creating if absent) a store at `path`.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the database cannot be opened or initialized.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory store. For tests and ephemeral sessions.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the in-memory database cannot be initialized.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Lock the connection, turning a poisoned mutex into a [`StoreError`] rather
    /// than a panic (the crate forbids `unwrap`/`expect`).
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.conn
            .lock()
            .map_err(|_| StoreError::Backend("intel store mutex poisoned".to_owned()))
    }

    fn init(conn: &Connection) -> Result<(), StoreError> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS intel_cache (
                namespace TEXT NOT NULL,
                key       TEXT NOT NULL,
                value     TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            )",
            [],
        )?;
        Ok(())
    }
}

impl IntelStore for SqliteStore {
    fn get(&self, namespace: &str, key: &str) -> Result<Option<String>, StoreError> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT value FROM intel_cache WHERE namespace = ?1 AND key = ?2")?;
        let mut rows = stmt.query((namespace, key))?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    fn put(&self, namespace: &str, key: &str, value: &str) -> Result<(), StoreError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO intel_cache (namespace, key, value) VALUES (?1, ?2, ?3)",
            (namespace, key, value),
        )?;
        Ok(())
    }
}
