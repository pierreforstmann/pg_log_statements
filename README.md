# pg_log_statements

pg_log_statements (PGLS) is a PostgreSQL extension that allows to log SQL statements for specific server processes: instead of setting `log_statement` parameter at instance level or database level, `log_statement` can be set for specific server processes.

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

PGLS has no GUC parameter and run `log_statement=all` for selected server processes.

PGLS can be used in 2 different ways:

1. Either by using the service process identified (pid)
2. Or by using a filter to enable logging from server process start to server process start (the filter clause specified which server processed will enable `log_statement=all`

Both modes are complementary and cannot be mixed:
- if pid mode has been used, PGLS allows to stop server process logging
- if filter mode has been used, PGLS does not allow to choose server process logging start and stop: server process logging starts at process creation and ends at process exit; filter usage only applies to new server process (existing server process cannot be selected in filter mode).

### Using server process by process identifier

To enable `log_statement` parameter for a specific server process, run:

    select pgls_start(<pid>):
  
To disable `log_statement` parameter for a specific server process, run:

    select pgls_stop(<pid>);
  
To check what is the current status of `log_statement` parameter for all server processes, run:

    select pgls_state();

  
