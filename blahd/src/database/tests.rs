#![expect(clippy::print_stdout, reason = "allowed in tests for debugging")]
use super::*;

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
    let src = std::fs::read_to_string("src/database.rs").unwrap();
    let sql_cnt = src.matches("prepare_cached_and_bind!").count();
    println!("found {sql_cnt} SQLs");
    assert_ne!(sql_cnt, 0);
    assert!(
        sql_cnt <= STMT_CACHE_CAPACITY,
        "stmt cache capacity {STMT_CACHE_CAPACITY} is too small, found {sql_cnt} SQLs",
    );
}
