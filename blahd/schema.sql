-- TODO: We are still in prototyping phase. Database migration is not
-- implemented and layout can change at any time.

CREATE TABLE IF NOT EXISTS `user` (
    `uid`               INTEGER NOT NULL PRIMARY KEY,
    `id_key`            BLOB NOT NULL UNIQUE,
    `permission`        INTEGER NOT NULL DEFAULT 0,
    `last_fetch_time`   INTEGER NOT NULL,
    `id_desc`           TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS `user_act_key` (
    `uid`           INTEGER NOT NULL REFERENCES `user` (`uid`),
    `act_key`       BLOB NOT NULL,
    `expire_time`   INTEGER NOT NULL,

    PRIMARY KEY (`uid`, `act_key`)
) STRICT, WITHOUT ROWID;

CREATE VIEW IF NOT EXISTS `valid_user_act_key` AS
    SELECT `act_key`, `user`.*
    FROM `user_act_key`
    JOIN `user` USING (`uid`)
    WHERE unixepoch() < `expire_time`;

-- The highest bit of `rid` will be set for peer chat room.
-- So simply comparing it against 0 can filter them out.
CREATE TABLE IF NOT EXISTS `room` (
    `rid`       INTEGER NOT NULL PRIMARY KEY,
    -- RoomAttrs::PEER_CHAT
    `attrs`     INTEGER NOT NULL
                CHECK ((`attrs` & 0x10000 == 0x10000) == `rid` < 0),
    `title`     TEXT
                CHECK ((`title` ISNULL) == `rid` < 0),

    `peer1`     INTEGER REFERENCES `user` ON DELETE RESTRICT
                CHECK ((`peer1` NOTNULL) == `rid` < 0),
    `peer2`     INTEGER REFERENCES `user` ON DELETE RESTRICT
                CHECK ((`peer2` NOTNULL AND `peer1` <= `peer2`) IS `rid` < 0)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS `ix_peer_chat` ON `room`
    (`peer1`, `peer2`)
    WHERE `rid` < 0;

CREATE TABLE IF NOT EXISTS `room_member` (
    `rid`           INTEGER NOT NULL REFERENCES `room` ON DELETE CASCADE,
    `uid`           INTEGER NOT NULL REFERENCES `user` ON DELETE RESTRICT,
    `permission`    INTEGER NOT NULL,
    -- Optionally references `msg`(`cid`).
    `last_seen_cid` INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (`rid`, `uid`)
) STRICT;

CREATE INDEX IF NOT EXISTS `ix_member_room` ON `room_member`
    (`uid` ASC, `rid` ASC, `permission`, `last_seen_cid`);

CREATE TABLE IF NOT EXISTS `msg` (
    `cid`       INTEGER NOT NULL PRIMARY KEY,
    `rid`       INTEGER NOT NULL REFERENCES `room` ON DELETE CASCADE,
    `uid`       INTEGER NOT NULL REFERENCES `user` ON DELETE RESTRICT,
    -- Optionally references `user_act_key`(`act_key`)
    `act_key`   BLOB NOT NULL,
    `timestamp` INTEGER NOT NULL,
    `nonce`     INTEGER NOT NULL,
    `sig`       BLOB NOT NULL,
    `rich_text` TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS `room_latest_msg` ON `msg` (`rid` ASC, `cid` DESC);
