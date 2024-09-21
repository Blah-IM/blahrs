#![expect(clippy::print_stdout, reason = "allowed in tests for debugging")]
use std::fmt::Write;
use std::fs;
use std::process::{Command, Stdio};

use super::*;

const SRC_PATH: &str = "src/database.rs";

#[test]
fn init_sql_valid() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(INIT_SQL).unwrap();

    // Instantiate view to check syntax and availability of `unixepoch()`.
    // It requires sqlite >= 3.38.0 (2022-02-22) which is not available by default on GitHub CI.
    let ret = conn
        .query_row(
            "SELECT COUNT(*) FROM `valid_user_act_key`",
            params![],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(ret, 0);
}

#[test]
fn stmt_cache_capacity() {
    let src = fs::read_to_string(SRC_PATH).unwrap();
    let sql_cnt = src.matches("prepare_cached_and_bind!").count();
    println!("found {sql_cnt} SQLs");
    assert_ne!(sql_cnt, 0);
    assert!(
        sql_cnt <= STMT_CACHE_CAPACITY,
        "stmt cache capacity {STMT_CACHE_CAPACITY} is too small, found {sql_cnt} SQLs",
    );
}

#[test]
#[ignore = "only for debugging"]
fn dump_query_plan() {
    let src = fs::read_to_string(SRC_PATH).unwrap();
    let mut cmds = String::new();
    for (pos, _) in src.match_indices("prepare_cached_and_bind!") {
        let line = src[..pos].matches('\n').count() + 1;
        let sql = src[pos..]
            .lines()
            // Skip macro call, first argument, `r"`.
            .skip(3)
            .take_while(|line| line.trim() != "\"")
            .flat_map(|line| [line.trim(), "\n"])
            .collect::<String>();
        writeln!(cmds, "SELECT '{SRC_PATH}:{line}';").unwrap();
        writeln!(cmds, "EXPLAIN QUERY PLAN {sql};").unwrap();
    }

    let st = Command::new("sqlite3")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .args([":memory:", ".read ./schema.sql", &cmds])
        .status()
        .unwrap();
    assert!(st.success());
}
