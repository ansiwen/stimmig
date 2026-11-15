CREATE TABLE IF NOT EXISTS reg_mail (
    election bytea NOT NULL REFERENCES reg_elections,
    key      bytea NOT NULL, -- keyed hash of provider and subject
    last     timestamptz NOT NULL,
    PRIMARY KEY (election, key)
);
CREATE INDEX IF NOT EXISTS reg_mail_last ON reg_mail (last);
CREATE INDEX IF NOT EXISTS reg_sessions_expires ON reg_sessions (expires);
