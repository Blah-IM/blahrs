use std::borrow::Borrow;
use std::ops::DerefMut;
use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use blah_types::{ServerPermission, UserKey};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_inline_default::serde_inline_default;

use crate::ApiError;

const DEFAULT_DATABASE_PATH: &str = "/var/lib/blahd/db.sqlite";

static INIT_SQL: &str = include_str!("../schema.sql");

// Simple and stupid version check for now.
// `echo -n 'blahd-database-0' | sha256sum | head -c5` || version
const APPLICATION_ID: i32 = 0xd9e_8405;

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub in_memory: bool,
    pub path: PathBuf,
    pub create: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            in_memory: false,
            path: DEFAULT_DATABASE_PATH.into(),
            create: true,
        }
    }
}

#[derive(Debug)]
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Use an existing database connection and do no initialization or schema checking.
    /// This should only be used for testing purpose.
    pub fn from_raw(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "TRUE")?;
        Ok(Self { conn: conn.into() })
    }

    pub fn open(config: &Config) -> Result<Self> {
        let mut conn = if config.in_memory {
            Connection::open_in_memory().context("failed to open in-memory database")?
        } else {
            let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            if !config.path.try_exists()? {
                flags.set(OpenFlags::SQLITE_OPEN_CREATE, config.create);
            }
            Connection::open_with_flags(&config.path, flags)
                .context("failed to connect database")?
        };
        Self::maybe_init(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn maybe_init(conn: &mut Connection) -> Result<()> {
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
        Ok(())
    }

    pub fn get(&self) -> impl DerefMut<Target = Connection> + '_ {
        self.conn.lock()
    }
}

pub trait ConnectionExt: Borrow<Connection> {
    fn get_user(&self, user: &UserKey) -> Result<(i64, ServerPermission), ApiError> {
        self.borrow()
            .query_row(
                r"
                SELECT `uid`, `permission`
                FROM `valid_user_act_key`
                WHERE (`id_key`, `act_key`) = (?, ?)
                ",
                params![user.id_key, user.act_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                error_response!(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "the user does not exist",
                )
            })
    }
}

impl ConnectionExt for Connection {}

#[test]
fn init_sql_valid() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(INIT_SQL).unwrap();
}
