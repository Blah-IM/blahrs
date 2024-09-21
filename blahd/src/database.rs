use std::path::PathBuf;

use anyhow::{ensure, Context};
use axum::http::StatusCode;
use blah_types::identity::UserIdentityDesc;
use blah_types::{
    ChatPayload, Id, MemberPermission, PubKey, RoomAttrs, RoomMetadata, ServerPermission,
    SignedChatMsg, Signee, UserKey, WithMsgId,
};
use parking_lot::Mutex;
use rusqlite::{named_params, params, prepare_cached_and_bind, Connection, OpenFlags, Row};
use serde::Deserialize;
use serde_inline_default::serde_inline_default;

use crate::ApiError;

#[cfg(test)]
mod tests;

const DEFAULT_DATABASE_PATH: &str = "/var/lib/blahd/db.sqlite";
const STMT_CACHE_CAPACITY: usize = 24;

static INIT_SQL: &str = include_str!("../schema.sql");

type Result<T, E = ApiError> = std::result::Result<T, E>;

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

pub struct Transaction<'db>(rusqlite::Transaction<'db>);

impl Database {
    /// Use an existing database connection and do no initialization or schema checking.
    /// This should only be used for testing purpose.
    pub fn from_raw(conn: Connection) -> anyhow::Result<Self> {
        conn.pragma_update(None, "foreign_keys", "TRUE")?;
        Ok(Self { conn: conn.into() })
    }

    pub fn open(config: &Config) -> anyhow::Result<Self> {
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
        conn.set_prepared_statement_cache_capacity(STMT_CACHE_CAPACITY);
        Self::maybe_init(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn maybe_init(conn: &mut Connection) -> anyhow::Result<()> {
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

    pub fn with_read<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        // TODO: Currently no concurrency is implemented.
        self.with_write(f)
    }

    pub fn with_write<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.conn.lock();
        let txn = Transaction(conn.transaction()?);
        match f(&txn) {
            Ok(v) => {
                txn.0.commit()?;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }
}

fn parse_msg(rid: Id, row: &Row<'_>) -> Result<WithMsgId<SignedChatMsg>> {
    Ok(WithMsgId {
        cid: row.get("cid")?,
        msg: SignedChatMsg {
            sig: row.get("sig")?,
            signee: Signee {
                nonce: row.get("nonce")?,
                timestamp: row.get("timestamp")?,
                user: UserKey {
                    id_key: row.get("id_key")?,
                    act_key: row.get("act_key")?,
                },
                payload: ChatPayload {
                    room: rid,
                    rich_text: row.get("rich_text")?,
                },
            },
        },
    })
}

fn parse_room_metadata(row: &Row<'_>) -> Result<RoomMetadata> {
    use rusqlite::types::ValueRef;

    let rid = row.get("rid")?;
    let last_msg = (matches!(row.get_ref("cid"), Ok(ValueRef::Integer(_))))
        .then(|| parse_msg(rid, row))
        .transpose()?;
    Ok(RoomMetadata {
        rid,
        title: row.get("title")?,
        attrs: row.get("attrs")?,
        last_msg,
        last_seen_cid: row.get("last_seen_cid").ok().filter(|&cid| cid != Id(0)),
        unseen_cnt: row.get("unseen_cnt").ok().filter(|&n| n != 0),
        member_permission: row.get("member_perm").ok(),
        peer_user: row.get("peer_id_key").ok(),
    })
}

pub trait TransactionOps {
    fn conn(&self) -> &Connection;

    fn get_user(&self, UserKey { id_key, act_key }: &UserKey) -> Result<(i64, ServerPermission)> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `uid`, `permission`
            FROM `valid_user_act_key`
            WHERE (`id_key`, `act_key`) = (:id_key, :act_key)
            "
        )
        .raw_query()
        .next()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::NOT_FOUND,
                "not_found",
                "the user does not exist",
            )
        })
        .and_then(|row| Ok((row.get(0)?, row.get(1)?)))
    }

    fn get_user_by_id_key(&self, id_key: &PubKey) -> Result<(i64, ServerPermission)> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `uid`, `permission`
            FROM `user`
            WHERE `id_key` = :id_key
            "
        )
        .raw_query()
        .next()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "the user does not exists",
            )
        })
        .and_then(|row| Ok((row.get(0)?, row.get(1)?)))
    }

    fn get_room_member(
        &self,
        rid: Id,
        UserKey { id_key, act_key }: &UserKey,
    ) -> Result<(i64, MemberPermission, Id)> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `uid`, `room_member`.`permission`, `last_seen_cid`
            FROM `room_member`
            JOIN `valid_user_act_key` USING (`uid`)
            WHERE (`rid`, `id_key`, `act_key`) = (:rid, :id_key, :act_key)
            "
        )
        .raw_query()
        .next()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::NOT_FOUND,
                "room_not_found",
                "the room does not exist or user is not a room member",
            )
        })
        .and_then(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
    }

    fn get_room_having(&self, rid: Id, filter: RoomAttrs) -> Result<(RoomAttrs, Option<String>)> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `attrs`, `title`
            FROM `room`
            WHERE `rid` = :rid
            "
        )
        .raw_query()
        .next()?
        .map(|row| {
            Ok::<_, rusqlite::Error>((
                row.get::<_, RoomAttrs>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        })
        .transpose()?
        .filter(|(attrs, _)| attrs.contains(filter))
        .ok_or_else(|| {
            error_response!(
                StatusCode::NOT_FOUND,
                "room_not_found",
                "the room does not exist"
            )
        })
    }

    // FIXME: Eliminate this.
    // Currently broadcasting msgs requires traversing over all members.
    fn list_room_members(&self, rid: Id) -> Result<Vec<i64>> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `uid`
            FROM `room_member`
            WHERE `rid` = :rid
            "
        )
        .raw_query()
        .mapped(|row| row.get::<_, i64>(0))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
    }

    fn list_public_rooms(&self, start_rid: Id, page_len: usize) -> Result<Vec<RoomMetadata>> {
        // Attribute check must be written in the SQL literal so the query planer
        // can successfully pick the conditional index.
        const _: () = assert!(RoomAttrs::PUBLIC_READABLE.bits() == 1);
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `rid`, `title`, `attrs`,
                MAX(`cid`) AS `cid`, `timestamp`, `nonce`, `sig`, `rich_text`,
                `last_author`.`id_key`, `msg`.`act_key`
            FROM `room` INDEXED BY `ix_public_room`
            LEFT JOIN `msg` USING (`rid`)
            LEFT JOIN `user` AS `last_author` USING (`uid`)
            WHERE `attrs` & 1 != 0 AND
                `rid` > :start_rid
            GROUP BY `rid`
            ORDER BY `rid` ASC
            LIMIT :page_len
            "
        )
        .raw_query()
        .and_then(parse_room_metadata)
        .collect()
    }

    fn list_joined_rooms(
        &self,
        uid: i64,
        start_rid: Id,
        page_len: usize,
    ) -> Result<Vec<RoomMetadata>> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT
                `rid`, `title`, `attrs`, `last_seen_cid`, `room_member`.`permission` AS `member_perm`,
                MAX(`cid`) AS `cid`, `timestamp`, `nonce`, `sig`, `rich_text`,
                `last_author`.`id_key`, `msg`.`act_key`,
                `peer_user`.`id_key` AS `peer_id_key`
            FROM `room_member` INDEXED BY `ix_member_room`
            JOIN `room` USING (`rid`)
            LEFT JOIN `msg` USING (`rid`)
            LEFT JOIN `user` AS `last_author` ON (`last_author`.`uid` = `msg`.`uid`)
            LEFT JOIN `user` AS `peer_user` ON
                (`peer_user`.`uid` = `room`.`peer1` + `room`.`peer2` - :uid)
            WHERE `room_member`.`uid` = :uid AND
                `rid` > :start_rid
            GROUP BY `rid`
            ORDER BY `rid` ASC
            LIMIT :page_len
            "
        )
        .raw_query()
        .and_then(parse_room_metadata)
        .collect()
    }

    fn list_unseen_rooms(
        &self,
        uid: i64,
        start_rid: Id,
        page_len: usize,
    ) -> Result<Vec<RoomMetadata>> {
        // FIXME: Limit `unseen_cnt` counting.
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT
                `rid`, `title`, `attrs`, `last_seen_cid`, `room_member`.`permission` AS `member_perm`,
                `cid`, `timestamp`, `nonce`, `sig`, `rich_text`,
                `last_author`.`id_key`, `msg`.`act_key`,
                `peer_user`.`id_key` AS `peer_id_key`,
                (SELECT COUNT(*)
                    FROM `msg` AS `unseen_msg`
                    WHERE `unseen_msg`.`rid` = `room`.`rid` AND
                        `last_seen_cid` < `unseen_msg`.`cid`) AS `unseen_cnt`
            FROM `room_member` INDEXED BY `ix_member_room`
            JOIN `room` USING (`rid`)
            LEFT JOIN `msg` USING (`rid`)
            LEFT JOIN `user` AS `last_author` ON (`last_author`.`uid` = `msg`.`uid`)
            LEFT JOIN `user` AS `peer_user` ON
                (`peer_user`.`uid` = `room`.`peer1` + `room`.`peer2` - :uid)
            WHERE `room_member`.`uid` = :uid AND
                `rid` > :start_rid AND
                `cid` > `last_seen_cid`
            GROUP BY `rid` HAVING `cid` IS MAX(`cid`)
            ORDER BY `rid` ASC
            LIMIT :page_len
            "
        )
        .raw_query()
        .and_then(parse_room_metadata)
        .collect()
    }

    fn list_room_msgs(
        &self,
        rid: Id,
        after_cid: Id,
        before_cid: Id,
        page_len: usize,
    ) -> Result<Vec<WithMsgId<SignedChatMsg>>> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT `cid`, `timestamp`, `nonce`, `sig`, `id_key`, `act_key`, `sig`, `rich_text`
            FROM `msg`
            JOIN `user` USING (`uid`)
            WHERE `rid` = :rid AND
                :after_cid < `cid` AND
                `cid` < :before_cid
            ORDER BY `cid` DESC
            LIMIT :page_len
            "
        )
        .raw_query()
        .and_then(|row| parse_msg(rid, row))
        .collect()
    }

    fn create_user(
        &self,
        id_desc: &UserIdentityDesc,
        id_desc_json: &str,
        fetch_time: u64,
    ) -> Result<i64> {
        let conn = self.conn();
        let id_key = &id_desc.id_key;
        let uid = prepare_cached_and_bind!(
            conn,
            r"
            INSERT INTO `user` (`id_key`, `last_fetch_time`, `id_desc`)
            VALUES (:id_key, :fetch_time, :id_desc_json)
            ON CONFLICT (`id_key`) DO UPDATE SET
                `last_fetch_time` = excluded.`last_fetch_time`,
                `id_desc` = excluded.`id_desc`
            WHERE `last_fetch_time` < :fetch_time
            RETURNING `uid`
            "
        )
        .raw_query()
        .next()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::CONFLICT,
                "conflict",
                "racing register, please try again later",
            )
        })
        .and_then(|row| Ok(row.get::<_, i64>(0)?))?;

        // Delete existing act_keys.
        prepare_cached_and_bind!(
            conn,
            r"
            DELETE FROM `user_act_key`
            WHERE `uid` = :uid
            "
        )
        .raw_execute()?;

        let mut stmt = conn.prepare_cached(
            r"
            INSERT INTO `user_act_key` (`uid`, `act_key`, `expire_time`)
            VALUES (:uid, :act_key, :expire_time)
            ",
        )?;
        for kdesc in &id_desc.act_keys {
            stmt.execute(named_params! {
                ":uid": uid,
                ":act_key": kdesc.signee.payload.act_key,
                // FIXME: Other `u64` that will be stored in database should also be range checked.
                ":expire_time": kdesc.signee.payload.expire_time.min(i64::MAX as _),
            })?;
        }

        Ok(uid)
    }

    fn create_group(&self, rid: Id, title: &str, attrs: RoomAttrs) -> Result<()> {
        prepare_cached_and_bind!(
            self.conn(),
            r"
            INSERT INTO `room` (`rid`, `title`, `attrs`)
            VALUES (:rid, :title, :attrs)
            "
        )
        .raw_execute()?;
        Ok(())
    }

    fn create_peer_room_with_members(
        &self,
        rid: Id,
        attrs: RoomAttrs,
        src_uid: i64,
        tgt_uid: i64,
    ) -> Result<()> {
        assert!(attrs.contains(RoomAttrs::PEER_CHAT));
        let conn = self.conn();
        let (p1, p2) = if src_uid <= tgt_uid {
            (src_uid, tgt_uid)
        } else {
            (tgt_uid, src_uid)
        };
        let updated = prepare_cached_and_bind!(
            conn,
            r"
            INSERT INTO `room` (`rid`, `attrs`, `peer1`, `peer2`)
            VALUES (:rid, :attrs, :p1, :p2)
            ON CONFLICT (`peer1`, `peer2`) WHERE `rid` < 0 DO NOTHING
            "
        )
        .raw_execute()?;
        if updated == 0 {
            return Err(error_response!(
                StatusCode::CONFLICT,
                "exists",
                "room already exists"
            ));
        }

        // TODO: Limit permission of the src user?
        let perm = MemberPermission::MAX_PEER_CHAT;
        prepare_cached_and_bind!(
            conn,
            r"
            INSERT INTO `room_member` (`rid`, `uid`, `permission`)
            VALUES (:rid, :src_uid, :perm), (:rid, :tgt_uid, :perm)
            "
        )
        .raw_execute()?;
        Ok(())
    }

    fn delete_room(&self, rid: Id) -> Result<bool> {
        let deleted = prepare_cached_and_bind!(
            self.conn(),
            r"
            DELETE FROM `room`
            WHERE `rid` = :rid
            "
        )
        .raw_execute()?;
        Ok(deleted == 1)
    }

    fn add_room_member(&self, rid: Id, uid: i64, perm: MemberPermission) -> Result<()> {
        let updated = prepare_cached_and_bind!(
            self.conn(),
            r"
            INSERT INTO `room_member` (`rid`, `uid`, `permission`)
            VALUES (:rid, :uid, :perm)
            ON CONFLICT (`rid`, `uid`) DO NOTHING
            "
        )
        .raw_execute()?;
        if updated != 1 {
            return Err(error_response!(
                StatusCode::CONFLICT,
                "exists",
                "the user already joined the room",
            ));
        }
        Ok(())
    }

    fn remove_room_member(&self, rid: Id, uid: i64) -> Result<bool> {
        // TODO: Check if it is the last member?
        let updated = prepare_cached_and_bind!(
            self.conn(),
            r"
            DELETE FROM `room_member`
            WHERE (`rid`, `uid`) = (:rid, :uid)
            "
        )
        .raw_execute()?;
        Ok(updated == 1)
    }

    fn add_room_chat_msg(&self, rid: Id, uid: i64, cid: Id, chat: &SignedChatMsg) -> Result<()> {
        let conn = self.conn();
        let act_key = &chat.signee.user.act_key;
        let timestamp = chat.signee.timestamp;
        let nonce = chat.signee.nonce;
        let rich_text = &chat.signee.payload.rich_text;
        let sig = &chat.sig;
        prepare_cached_and_bind!(
            conn,
            r"
            INSERT INTO `msg` (`cid`, `rid`, `uid`, `act_key`, `timestamp`, `nonce`, `sig`, `rich_text`)
            VALUES (:cid, :rid, :uid, :act_key, :timestamp, :nonce, :sig, :rich_text)
            "
        )
        .raw_execute()?;
        Ok(())
    }

    fn mark_room_msg_seen(&self, rid: Id, uid: i64, cid: Id) -> Result<()> {
        let max_cid_in_room = prepare_cached_and_bind!(
            self.conn(),
            r"
            SELECT MAX(`cid`)
            FROM `msg` INDEXED BY `room_latest_msg`
            WHERE `rid` = :rid
            "
        )
        .raw_query()
        .next()?
        .map(|row| row.get(0))
        .transpose()?
        .unwrap_or(Id(0));
        if max_cid_in_room < cid {
            return Err(error_response!(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid cid",
            ));
        }
        let updated = prepare_cached_and_bind!(
            self.conn(),
            r"
            UPDATE `room_member`
            SET `last_seen_cid` = MAX(`last_seen_cid`, :cid)
            WHERE (`rid`, `uid`) = (:rid, :uid)
            "
        )
        .raw_execute()?;
        if updated != 1 {
            return Err(error_response!(
                StatusCode::NOT_FOUND,
                "room_not_found",
                "the room does not exist or the user is not a room member",
            ));
        }

        Ok(())
    }
}

impl TransactionOps for Transaction<'_> {
    fn conn(&self) -> &Connection {
        &self.0
    }
}
