-- \echo Use "CREATE EXTENSION pg_log_statement" to load this file . \quit
DROP FUNCTION IF EXISTS pgls_start();
DROP FUNCTION IF EXISTS pgls_stop();
DROP FUNCTION IF EXISTS pgls_state();
--
CREATE FUNCTION pgls_start(int) RETURNS bool
 AS 'pg_log_statements.so', 'pgls_start'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_stop(int) RETURNS bool
 AS 'pg_log_statements.so', 'pgls_stop'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_state() RETURNS setof record
 AS 'pg_log_statements.so', 'pgls_state'
 LANGUAGE C STRICT;
--
