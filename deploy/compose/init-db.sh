#!/bin/sh
# Runs once, when the database volume is created: one database and one role
# per service, and no role may connect to another service's database.
set -eu
psql -v ON_ERROR_STOP=1 --username postgres <<SQL
CREATE ROLE log LOGIN PASSWORD '$LOG_DB_PASSWORD';
CREATE ROLE registrar LOGIN PASSWORD '$REGISTRAR_DB_PASSWORD';
CREATE ROLE ballotbox LOGIN PASSWORD '$BALLOTBOX_DB_PASSWORD';
CREATE DATABASE stimmig_log OWNER log;
CREATE DATABASE stimmig_reg OWNER registrar;
CREATE DATABASE stimmig_box OWNER ballotbox;
REVOKE ALL ON DATABASE stimmig_log, stimmig_reg, stimmig_box FROM PUBLIC;
SQL
