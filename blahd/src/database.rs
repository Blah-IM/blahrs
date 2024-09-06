use std::ops::DerefMut;

use anyhow::{ensure, Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags};

use crate::config::DatabaseConfig;

static INIT_SQL: &str = include_str!("../schema.sql");

// Simple and stupid version check for now.
// `echo -n 'blahd-database-0' | sha256sum | head -c5` || version
const APPLICATION_ID: i32 = 0xd9e_8403;

#[derive(Debug)]
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(config: &DatabaseConfig) -> Result<Self> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if !config.path.try_exists()? {
            flags.set(OpenFlags::SQLITE_OPEN_CREATE, config.create);
        }

        let mut conn = Connection::open_with_flags(&config.path, flags)
            .context("failed to connect database")?;
        // Connection-specific pragmas.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "TRUE")?;

        if conn.query_row(r"SELECT COUNT(*) FROM sqlite_schema", params![], |row| {
            row.get::<_, u64>(0)
        })? != 0
        {
            let cur_app_id =
                conn.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?;
            ensure!(
                cur_app_id == (APPLICATION_ID),
                "database is non-empty with a different application_id. \
                migration is not implemented yet. \
                got: {cur_app_id:#x}, expect: {APPLICATION_ID:#x} \
                ",
            );
        }

        let txn = conn.transaction()?;
        txn.execute_batch(INIT_SQL)
            .context("failed to initialize database")?;
        txn.pragma_update(None, "application_id", APPLICATION_ID)?;
        txn.commit()?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn get(&self) -> impl DerefMut<Target = Connection> + '_ {
        self.conn.lock()
    }
}

#[test]
fn init_sql_valid() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(INIT_SQL).unwrap();
}
