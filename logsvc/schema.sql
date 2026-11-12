CREATE TABLE IF NOT EXISTS log_keys (
    public   bytea PRIMARY KEY,
    private  bytea NOT NULL,
    election bytea UNIQUE -- set when the key is bound to its election
);
CREATE TABLE IF NOT EXISTS log_elections (
    id   bytea PRIMARY KEY,
    tree bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS log_entries (
    election bytea  NOT NULL REFERENCES log_elections,
    idx      bigint NOT NULL,
    entry    bytea  NOT NULL,
    leaf     bytea  NOT NULL,
    PRIMARY KEY (election, idx)
);
CREATE TABLE IF NOT EXISTS log_heads (
    seq      bigserial PRIMARY KEY,
    election bytea NOT NULL REFERENCES log_elections,
    head     bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS log_heads_election ON log_heads (election, seq);
