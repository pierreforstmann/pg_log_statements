# pg_log_statements

pg_log_statements is a PostgreSQL extension that allows to log SQL statements for specific database sessions: instead of setting `log_statement` parameter at instance level or database level, log_statement can be set for specific server processes.

## Installation
### Compiling

This module can be built using the standard PGXS infrastructure. For this to work, the `pg_config` program must be available in your $PATH:


    git clone https://github.com/pierreforstmann/pg_log_statements.git 
    cd pg_log_statements 
    make 
    make install 


### PostgreSQL setup

Extension must be loaded at server level with `shared_preload_libraries` parameter:

    shared_preload_libraries = 'pg_log_statements'
     

It must also be created with following SQL statement at server level:

    create extension pg_log_statements;

This extension has been validated with PostgreSQL 9.5, 9.6, 10, 11, 12 and 13.

## Usage

`pg_log_statements` has no GUC parameter and run `log_statement=all` for selected server processes.

To enable `log_statement` parameter for a specific server process, run:

    select pgls_start(<pid>):
  
To disable `log_statement` parameter for a specific server process, run:

    select pgls_stop(<pid>);
  
To check what is the current status of `log_statement` parameter for all server processes, run:

    select pgls_state();

  
