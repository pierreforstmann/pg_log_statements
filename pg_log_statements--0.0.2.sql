-- \echo Use "CREATE EXTENSION pg_log_statement" to load this file . \quit
DROP FUNCTION IF EXISTS pgls_start();
DROP FUNCTION IF EXISTS pgls_stop();
DROP FUNCTION IF EXISTS pgls_start_filter();
DROP FUNCTION IF EXISTS pgls_stop_filter();
DROP FUNCTION IF EXISTS pgls_state();
DROP FUNCTION IF EXISTS pgls_start_debug();
DROP FUNCTION IF EXISTS pgls_stop_debug();
--
CREATE FUNCTION pgls_start(int) RETURNS bool
 AS 'pg_log_statements.so', 'pgls_start'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_stop(int) RETURNS bool
 AS 'pg_log_statements.so', 'pgls_stop'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_start_filter(cstring, cstring) RETURNS bool
 AS 'pg_log_statements.so', 'pgls_start_filter'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_stop_filter(cstring, cstring) RETURNS bool
 AS 'pg_log_statements.so', 'pgls_stop_filter'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_state() RETURNS setof record
 AS 'pg_log_statements.so', 'pgls_state'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_conf() RETURNS setof record
 AS 'pg_log_statements.so', 'pgls_conf'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_start_debug() RETURNS bool 
 AS 'pg_log_statements.so', 'pgls_start_debug'
 LANGUAGE C STRICT;
--
CREATE FUNCTION pgls_stop_debug() RETURNS bool 
 AS 'pg_log_statements.so', 'pgls_stop_debug'
 LANGUAGE C STRICT;
