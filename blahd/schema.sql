-- TODO: We are still in prototyping phase. Database migration is not
-- implemented and layout can change at any time.

CREATE TABLE IF NOT EXISTS `user` (
    `uid`           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `userkey`       BLOB NOT NULL UNIQUE,
    `permission`    INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS `room` (
    `rid`       INTEGER NOT NULL PRIMARY KEY,
    `title`     TEXT NOT NULL,
    `attrs`     INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS `room_member` (
    `rid`           INTEGER NOT NULL REFERENCES `room` ON DELETE CASCADE,
    `uid`           INTEGER NOT NULL REFERENCES `user` ON DELETE RESTRICT,
    `permission`    INTEGER NOT NULL,
    PRIMARY KEY (`rid`, `uid`)
) STRICT;

CREATE INDEX IF NOT EXISTS `member_room` ON `room_member` (`uid` ASC, `rid` ASC);

CREATE TABLE IF NOT EXISTS `room_item` (
    `cid`       INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `rid`       INTEGER NOT NULL REFERENCES `room` ON DELETE CASCADE,
    `uid`       INTEGER NOT NULL REFERENCES `user` ON DELETE RESTRICT,
    `timestamp` INTEGER NOT NULL,
    `nonce`     INTEGER NOT NULL,
    `sig`       BLOB NOT NULL,
    `rich_text` TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS `room_latest_item` ON `room_item` (`rid` ASC, `cid` DESC);
