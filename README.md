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

1. Either by using the server process identifier (pid): pid mode
2. Or by using a filter to enable logging from server process start to server process end (the filter clause specifies which server processed are going to enable `log_statement=all`): filter mode

Both modes are complementary and cannot be mixed:
- if pid mode has been used, PGLS allows to stop server process logging
- if filter mode has been used, PGLS does not allow to choose server process logging start or stop: server process logging starts at process creation and ends at process exit; filter mode only applies to new server processes (existing server processes cannot be selected in filter mode).

### Using pid mode

To enable `log_statement` parameter for a specific server process, run:

    select pgls_start(pid):
  
To disable `log_statement` parameter for a specific server process, run:

    select pgls_stop(pid);
  
To check what is the current status of `log_statement` parameter for all server processes, run:

    select pgls_state();

### Using filter mode

To enable `log_statement` parameter for new server process started by a specific application, run:

`select pgls_filter('application_name', 'your_application');`

To enable `log_statement` parameter for new server process started by some specific PostgreSQL user, run:

`select pgls_filter('user_name', 'your_user');`
    
To enable `log_statement` parameter for new server process started from some specific host name, run:

`select pgls_filter('hostname', 'your_hostname');`
    
To enable `log_statement` parameter for new server process started from some specific IP address, run:

`select pgls_filter('ip_address', 'your_IP_address');`
    
To enable `log_statement` parameter for new server process started for some specific database, run:

`select pgls_filter('database_name', 'your_database_name');`
    
Current filter mode configuration can be listed with:

`select pgls_conf();`
    
Filter mode is using parameters defined in `Port` structure (see `libpq-be.h`) used for frontend/backend communication.
These parameters can be logged using following functions:
   
To start parameters logging at server process creation time, run:

`select pgls_start_debug();`
    
To stop parameters logging at server process creation time, run:

`select pgls_stop_debug();`
    

