PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=TRUE;

CREATE TABLE IF NOT EXISTS `user` (
    `uid`           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `userkey`       BLOB NOT NULL UNIQUE,
    `permission`    INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS `room` (
    `rid`       INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `ruuid`     BLOB NOT NULL UNIQUE,
    `title`     TEXT NOT NULL,
    `attrs`     INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS `room_member` (
    `rid`           INTEGER NOT NULL REFERENCES `room` ON DELETE CASCADE,
    `uid`           INTEGER NOT NULL REFERENCES `user` ON DELETE RESTRICT,
    `permission`    INTEGER NOT NULL,
    PRIMARY KEY (`rid`, `uid`)
) STRICT;

CREATE TABLE IF NOT EXISTS `room_item` (
    `cid`       INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `rid`       INTEGER NOT NULL REFERENCES `room` ON DELETE CASCADE,
    `uid`       INTEGER NOT NULL REFERENCES `user` ON DELETE RESTRICT,
    `timestamp` INTEGER NOT NULL,
    `nonce`     INTEGER NOT NULL,
    `sig`       BLOB NOT NULL,
    `message`   TEXT NOT NULL
) STRICT;
