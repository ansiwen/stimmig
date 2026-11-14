CREATE TABLE IF NOT EXISTS reg_keys (
    issuing_public   bytea PRIMARY KEY,
    issuing_private  bytea NOT NULL,
    election_public  bytea NOT NULL,
    election_private bytea NOT NULL,
    election         bytea UNIQUE -- set when the keys are bound to their election
);
CREATE TABLE IF NOT EXISTS reg_elections (
    id       bytea PRIMARY KEY,
    manifest bytea  NOT NULL,
    salt     bytea  NOT NULL,
    phase    text   NOT NULL, -- setup, open, closed
    issued   bigint NOT NULL DEFAULT 0,
    log_size bigint NOT NULL DEFAULT 1
);
-- One row per eligible voter. The primary key allows one credential per
-- roll reference; seq, blinded and blind_sig are set when it is issued.
CREATE TABLE IF NOT EXISTS reg_roll (
    election  bytea NOT NULL REFERENCES reg_elections,
    ref       bytea NOT NULL,
    seq       bigint,
    blinded   bytea,
    blind_sig bytea,
    PRIMARY KEY (election, ref)
);
CREATE TABLE IF NOT EXISTS reg_sessions (
    id       text PRIMARY KEY,
    election bytea NOT NULL REFERENCES reg_elections,
    blinded  bytea NOT NULL,
    ref      bytea, -- set when the voter has logged in
    code     text NOT NULL, -- the voter types it after the login
    attempts int  NOT NULL DEFAULT 0,
    expires  timestamptz NOT NULL
);
