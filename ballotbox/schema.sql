CREATE TABLE IF NOT EXISTS box_keys (
    public   bytea PRIMARY KEY,
    private  bytea NOT NULL,
    election bytea UNIQUE -- set when the key is bound to its election
);
CREATE TABLE IF NOT EXISTS box_elections (
    id       bytea PRIMARY KEY,
    manifest bytea NOT NULL,
    phase    text  NOT NULL -- setup, open, closed, published
);
-- The primary key allows one ballot per credential.
CREATE TABLE IF NOT EXISTS box_ballots (
    election   bytea NOT NULL REFERENCES box_elections,
    credential bytea NOT NULL,
    ballot     bytea NOT NULL,
    PRIMARY KEY (election, credential)
);
