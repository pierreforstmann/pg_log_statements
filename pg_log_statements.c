/*-------------------------------------------------------------------------
 *  
 * pg_log_statements is a PostgreSQL extension which allows to log SQL statements 
 * for specific backends.
 *  
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *          
 * Copyright (c) 2021, Pierre Forstmann.
 *            
 *-------------------------------------------------------------------------
*/
#include "postgres.h"
#include "parser/analyze.h"
#include "nodes/nodes.h"
#include "storage/proc.h"
#include "access/xact.h"

#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/snapmgr.h"
#include "utils/memutils.h"
#if PG_VERSION_NUM <= 90600
#include "storage/lwlock.h"
#endif
#if PG_VERSION_NUM < 120000 
#include "access/transam.h"
#endif
#include "utils/varlena.h"
#include "utils/hsearch.h"

#include "utils/queryenvironment.h"
#include "tcop/cmdtag.h"

#include "nodes/nodes.h"

#include "storage/ipc.h"
#include "storage/spin.h"
#include "miscadmin.h"
#include "storage/procarray.h"
#include "executor/executor.h"

#include "fmgr.h"
#include "funcapi.h"
#include "catalog/pg_type.h"

#include "libpq/auth.h"
#include "common/ip.h"

PG_MODULE_MAGIC;

/*
 *
 * Global shared state
 * 
 */


typedef enum {
	pgls_application_name,
        pgls_hostname,
	pgls_ip_address,
	pgls_user_name,
        pgls_database_name
} pgls_filter_type;
/*
 *  maximum filter length
 */
#define	PGLS_MFL	20
/*
 * maximum filter number
 */
#define PGLS_MFN	5

typedef enum {
	pgls_none,
	pgls_to_start,
        pgls_to_stop,
        pgls_started,
        pgls_stopped
} pgls_status;

typedef struct pglsProc
{
	int 		pid;
	pgls_status	status;
} pglsProc;

typedef struct pglsFilter
{
	pgls_filter_type	type;
	char			filter[PGLS_MFL];
} pglsFilter;

typedef struct pglsSharedState
{
	LWLock	   	*lock;			/* self protection */
	/*
 	 * backend array
 	 */
        pglsProc	*procs;
	int		current_proc_num;
	/*
 	 * filter array
 	 */
	pglsFilter	*filters;
	int		current_filter_num;
	/*
 	 * debug flag
 	 */
	bool		debug;
	
} pglsSharedState;

/* Saved hook values in case of unload */
#if PG_VERSION_NUM >= 150000
static shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static ExecutorStart_hook_type prev_executor_start_hook = NULL;
static ClientAuthentication_hook_type next_client_auth_hook = NULL;

/* Links to shared memory state */
static pglsSharedState *pgls= NULL;

static bool pgls_enabled = false;

/*
 *
 * ---- Function declarations ----
 * 
 */

static void pgls_set_log(void);
static void pgls_vacuum(void);
static bool pgls_start_internal(int pid);
static bool pgls_stop_internal(int pid);
static Datum pgls_state_internal(FunctionCallInfo fcinfo);
static void pgls_auth_debug(Port *port);
static void pgls_auth(Port *port, int status);
static bool pgls_start_filter_internal(char *filter_name, char *filter_value);
static bool pgls_stop_filter_internal(char *filter_name, char *filter_value);
static Datum pgls_conf_internal(FunctionCallInfo fcinfo);
static bool pgls_start_debug_internal();
static bool pgls_stop_debug_internal();


PG_FUNCTION_INFO_V1(pgls_start);
PG_FUNCTION_INFO_V1(pgls_stop);
PG_FUNCTION_INFO_V1(pgls_state);
PG_FUNCTION_INFO_V1(pgls_stop_filter);
PG_FUNCTION_INFO_V1(pgls_start_filter);
PG_FUNCTION_INFO_V1(pgls_conf);
PG_FUNCTION_INFO_V1(pgls_start_debug);
PG_FUNCTION_INFO_V1(pgls_stop_debug);

void		_PG_init(void);
void		_PG_fini(void);

static void pgls_shmem_request(void);
static void pgls_shmem_startup(void);
static void pgls_shmem_shutdown(int code, Datum arg);

static void pgls_esexec(QueryDesc *queryDesc, int eflags);

static void pgls_puexec(
#if PG_VERSION_NUM < 100000
		      Node *parsetree,
#else
		      PlannedStmt *pstmt,
#endif
		      const char *queryString,
#if PG_VERSION_NUM >=140000
                      bool readOnlyTree,
#endif
		      ProcessUtilityContext context,
		      ParamListInfo params,
#if PG_VERSION_NUM > 100000
	              QueryEnvironment *queryEnv,
#endif
		      DestReceiver *dest,
#if PG_VERSION_NUM < 130000
                      char *CompletionTag
#else
	              QueryCompletion *qc
#endif
);


/*
 *
 * ---- Function definitions ----
 * 
 */

/*
 * Estimate shared memory space needed.
 */
static Size
pgls_memsize(void)
{
	Size		size;

	size = MAXALIGN(sizeof(pglsSharedState));

	return size;
}

/*
 * shmen_request_hook
 */
static void 
pgls_shmem_request(void)
{
	/*
 	 * Request additional shared resources.  (These are no-ops if we're not in
 	 * the postmaster process.)  We'll allocate or attach to the shared
 	 * resources in pgls_shmem_startup().
	 */

#if PG_VERSION_NUM >= 150000 
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();
#endif

	RequestAddinShmemSpace(pgls_memsize());
#if PG_VERSION_NUM >= 90600
	RequestNamedLWLockTranche("pg_log_statements", 1);
#endif

}

/*
 * shmem_startup hook: allocate or attach to shared memory.
 *
 */
static void
pgls_shmem_startup(void)
{

	bool		found;
	pglsProc	*procs;
	pglsFilter	*filters;
	int		i;

	elog(DEBUG5, "pg_log_statements: pgls_shmem_request: entry");


	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* reset in case this is a restart within the postmaster */
	pgls = NULL;


	/*
 	** Create or attach to the shared memory state
 	**/
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
	pgls = ShmemInitStruct("pg_log_statements",
			        sizeof(pglsSharedState),
			        &found);
	if (!found)
	{
		/* First time through ... */
#if PG_VERSION_NUM <= 90600
		RequestAddinLWLocks(1);
		pgls->lock = LWLockAssign();
#else
		pgls->lock = &(GetNamedLWLockTranche("pg_log_statements"))->lock;
#endif
	
	}

	elog(LOG, "pg_log_statements: pgls_shmem_request: MaxBackends=%d", 
                   MaxBackends);
	procs = (pglsProc *)ShmemAlloc(MaxBackends * sizeof(pglsProc));
	MemSet(procs, 0, MaxBackends * sizeof(pglsProc));
	for (i=0; i < MaxBackends; i++)
	{
		procs[i].pid = 0;
		procs[i].status = pgls_none;
	}
	pgls->procs = procs;
	pgls->current_proc_num = 0;

	filters = (pglsFilter *)ShmemAlloc(PGLS_MFN * sizeof(pglsFilter));
	MemSet(filters, 0, PGLS_MFN * sizeof(pglsFilter));
	pgls->current_filter_num = 0;
	pgls->filters = filters;
	
	pgls->debug = false;

	LWLockRelease(AddinShmemInitLock);

	/*
         * If we're in the postmaster (or a standalone backend...), set up a shmem
         * exit hook (no current need ???) 
         */ 
        if (!IsUnderPostmaster)
		on_shmem_exit(pgls_shmem_shutdown, (Datum) 0);

	/*
  	 * Done if some other process already completed our initialization.
  	 */
	if (found)
		return;

	pgls_enabled = true;
	elog(LOG, "pg_log_statements: pgls_shmem_request: pg_log_statements is enabled");

	elog(DEBUG5, "pg_log_statements: pgls_shmem_request: exit");

}

/*
 *
 *  shmem_shutdown hook
 *   
 *  Note: we don't bother with acquiring lock, because there should be no
 *  other processes running when this is called.
 */
static void
pgls_shmem_shutdown(int code, Datum arg)
{
	elog(DEBUG5, "pg_log_statements: pgls_shmem_shutdown: entry");

	/* Don't do anything during a crash. */
	if (code)
		return;

	/* Safety check ... shouldn't get here unless shmem is set up. */
	if (!pgls)
		return;
	
	/* currently: no action */

	elog(DEBUG5, "pg_log_statements: pgls_shmem_shutdown: exit");
}


/*
 * Module load callback
 */
void
_PG_init(void)
{
	elog(DEBUG5, "pg_log_statements: _PG_init(): entry");
	
	elog(LOG, "pg_log_statements:_PG_init(): pg_log_statements extension detected");


	/*
 	 * Install hooks
	 */
#if PG_VERSION_NUM >= 150000
	prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = pgls_shmem_request;
#else
	pgls_shmem_request();
#endif
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgls_shmem_startup;
	prev_executor_start_hook = ExecutorStart_hook;
 	ExecutorStart_hook = pgls_esexec;	
	prev_process_utility_hook = ProcessUtility_hook;
 	ProcessUtility_hook = pgls_puexec;	
        next_client_auth_hook = ClientAuthentication_hook; 
        ClientAuthentication_hook = pgls_auth;          

	elog(DEBUG5, "pg_log_statements: _PG_init(): exit");
}


/*
 *  Module unload callback
 */
void
_PG_fini(void)
{
	elog(DEBUG5, "pg_log_statements: _PG_fini(): entry");

	/* Uninstall hooks. */
#if PG_VERSION_NUM >= 150000
	shmem_request_hook = prev_shmem_request_hook;
#endif
	shmem_startup_hook = prev_shmem_startup_hook;
	ProcessUtility_hook = prev_process_utility_hook;
	ClientAuthentication_hook = next_client_auth_hook;

	elog(DEBUG5, "pg_log_statements: _PG_fini(): exit");
}

/*
 *
 * pgls_set_log
 *
 */

static void pgls_set_log()
{
	int 	i;
	bool	found = false;

	if (pgls_enabled == true)
	{

		pgls_vacuum();

		elog(DEBUG1, "MyProcPid=%d", MyProcPid);

		LWLockAcquire(pgls->lock, LW_EXCLUSIVE);

		for (i=0; i < pgls->current_proc_num && found == false; i++)
        	{
				         
			if (pgls->procs[i].pid == MyProcPid &&
			    pgls->procs[i].status == pgls_to_start)
			{
			        SetConfigOption("log_statement", "all", PGC_SUSET, PGC_S_CLIENT);
				pgls->procs[i].status = pgls_started;
				found = true;
				elog(LOG, "pg_log_statements: log_statement=all for %d", MyProcPid);
			}
			if (pgls->procs[i].pid == MyProcPid &&
			    pgls->procs[i].status == pgls_to_stop)
			{
			        SetConfigOption("log_statement", "none", PGC_SUSET, PGC_S_CLIENT);
				pgls->procs[i].status = pgls_stopped;
				found = true;
				elog(LOG, "pg_log_statements: log_statement=none for %d", MyProcPid);
			}
                }
		LWLockRelease(pgls->lock);
		
        }
}
/*
 *
 * pgls_esexec
 *
 */
static void pgls_esexec(
	QueryDesc *queryDesc, 
  	int eflags
)
{
	elog(DEBUG1, "pg_log_statements: pgls_esexec: entry");

	pgls_set_log();

	if (prev_executor_start_hook)
                (*prev_executor_start_hook)(queryDesc, eflags);
	else	standard_ExecutorStart(queryDesc, eflags);

	elog(DEBUG1, "pg_log_statements: pgls_esexec: exit");
}

/*
 *
 * pgls_puexec
 *
 */
static void
pgls_puexec(
#if PG_VERSION_NUM < 100000
	  Node *parsetree,
#else
	  PlannedStmt *pstmt,
#endif
	  const char *queryString,
#if PG_VERSION_NUM >= 140000
	  bool readOnlyTree,
#endif
	  ProcessUtilityContext context,
	  ParamListInfo params,
#if PG_VERSION_NUM > 100000
	  QueryEnvironment *queryEnv,
#endif
	  DestReceiver *dest,
#if PG_VERSION_NUM < 130000
	  char *CompletionTag)
#else
	  QueryCompletion *qc)
#endif

{
#if PG_VERSION_NUM > 100000
	Node	   	*parsetree;
#endif
	VariableSetStmt	*setstmt;

	elog(DEBUG1, "pg_log_statements: pgls_puexec: entry");
#if PG_VERSION_NUM > 100000
	parsetree = pstmt->utilityStmt;
#endif



	if (nodeTag(parsetree) == T_VariableSetStmt)
	{
		setstmt = (VariableSetStmt *)parsetree;
		if (setstmt->kind == VAR_SET_VALUE || setstmt->kind == VAR_SET_CURRENT)
		{

			elog(DEBUG1, "pg_log_statements: pgls_exec: setstmt->name=%s", setstmt->name);
			
		}
	}

	pgls_set_log();

	/*
 	 * see src/backend/tcop/utility.c
 	 */

	if (prev_process_utility_hook)

                (*prev_process_utility_hook) (
#if PG_VERSION_NUM < 100000
						  parsetree,
#else
						  pstmt, 
#endif
						  queryString,
#if PG_VERSION_NUM >= 140000
						  readOnlyTree,
#endif
						  context, 
						  params,
#if PG_VERSION_NUM > 100000
						  queryEnv,
#endif
					   	  dest, 
#if PG_VERSION_NUM < 130000
						  CompletionTag);
#else
                                                  qc);
#endif
	else	standard_ProcessUtility(
#if PG_VERSION_NUM < 100000
					parsetree,
#else
					pstmt, 
#endif
					queryString,
#if PG_VERSION_NUM >= 140000
					readOnlyTree,
#endif
				       	context,
					params, 
#if PG_VERSION_NUM > 100000
					queryEnv,
#endif
					dest, 
#if PG_VERSION_NUM < 130000
					CompletionTag);
#else
                                        qc);
#endif

	elog(DEBUG1, "pg_log_statements: pgls_puexec: exit");
}

/*
 *
 * pgls_add_backend (caller must have locked pglsSharedState)
 *
 */
static void pgls_add_backend(int pid, pgls_status status )
{
	
	if (pgls->current_proc_num == MaxBackends)	
		ereport(ERROR, (errmsg("Too many pending logging requests")));

	pgls->procs[pgls->current_proc_num].pid = pid;
	pgls->procs[pgls->current_proc_num].status = status;
	pgls->current_proc_num++;

}

/*
 *
 * pgls_start_internal
 * logging request is processed for matched backend process identifier
 * (behaviour different from logging request using filter like application name)
 *
 */
static bool pgls_start_internal(int pid)
{
	int 	i;
	bool	found = false;


	LWLockAcquire(pgls->lock, LW_EXCLUSIVE);

	for (i=0; i < pgls->current_proc_num && found == false; i++)
	{
		if (pgls->procs[i].pid == pid)
		{
			found = true;
			switch(pgls->procs[i].status)
			{
				
				case pgls_to_stop:
						pgls->procs[i].status = pgls_to_start;	
						break;
                     		case pgls_stopped:
						pgls->procs[i].status = pgls_to_start;	
						break;

                     		case pgls_to_start:
						LWLockRelease(pgls->lock);
						ereport(ERROR, (errmsg("logging request for %d is pending", pid)));
						break;

                     		case pgls_started:
						LWLockRelease(pgls->lock);
						ereport(ERROR, (errmsg("logging request for %d is already running", pid)));
						break;
               			case pgls_none: 
						LWLockRelease(pgls->lock);
						ereport(ERROR, (errmsg("unexpected pgls_none status for %d", pid)));
						break;
               			default: 
						LWLockRelease(pgls->lock);
						ereport(ERROR, (errmsg("unknown status for %d", pid)));
						break;
			}

		}
	}

	if (found == false)	
		pgls_add_backend(pid, pgls_to_start);

	LWLockRelease(pgls->lock);


	return true;
}

/*
 *
 * pgls_stop_internal
 *
 */
static bool pgls_stop_internal(int pid)
{
	int 	i;
	bool	found = false;

	LWLockAcquire(pgls->lock, LW_EXCLUSIVE);
	
	for (i=0; i < pgls->current_proc_num && found == false; i++)
	{
	 	elog(DEBUG5, "pgls_stop pid=%d i=%d found=%d ", pid, i , found);

		if (pgls->procs[i].pid == pid)
		{
			found = true;
			switch(pgls->procs[i].status)
			{
				
			case pgls_started:
						pgls->procs[i].status = pgls_to_stop;
 						break;

                    	case pgls_to_start:
						pgls->procs[i].status = pgls_stopped;
						break;

			case pgls_to_stop:
						LWLockRelease(pgls->lock);
						ereport(ERROR,
							(errmsg("logging stop request for %d is already pending", pid)));
						break;
                    	case pgls_stopped:
                
						LWLockRelease(pgls->lock);
						ereport(ERROR,
							(errmsg("logging for %d is already stopped", pid)));
						break;
               		case pgls_none: 
						LWLockRelease(pgls->lock);
						ereport(ERROR, (errmsg("unexpected pgls_none status for %d", pid)));
						break;
               		default: 
						LWLockRelease(pgls->lock);
						ereport(ERROR, (errmsg("unknown status for %d", pid)));
						break;
			}
		}

	}
	elog(DEBUG5, "pgls_stop pid=%d i=%d found=%d ", pid, i , found);

	/*
 	 * we don't store history of logging start and stop requests
 	 */		

	LWLockRelease(pgls->lock);

	if (found == false)	
	{
		ereport(ERROR, (errmsg("no logging for %d", pid)));
	}

	if (i == MaxBackends) 
		ereport(ERROR,
			(errmsg("Too many pending logging requests: %d", i)));

	return true;
}

/*
 *
 * pgls_start
 *
 */
Datum pgls_start(PG_FUNCTION_ARGS)
{
	 int pid;
	 PGPROC	   *proc;
         
	 pid = PG_GETARG_INT32(0);
	 elog(DEBUG5, "pgls_start_log pid=%d", pid);

	 proc = BackendPidGetProc(pid);
	 if (proc == NULL)
	 {
		ereport(ERROR,
			(errmsg("PID %d is not a PostgreSQL server process", pid)));
         }
	 elog(DEBUG5, "pgls_start pid=%d is valid", pid);

	 PG_RETURN_BOOL(pgls_start_internal(pid));
}
/*
 *
 * pgls_stop
 * 
 */
Datum pgls_stop(PG_FUNCTION_ARGS)
{
	 int pid;
	 PGPROC	   *proc;
	
	 pid = PG_GETARG_INT32(0);
	 elog(DEBUG5, "pgls_stop_log pid=%d", pid);

	 proc = BackendPidGetProc(pid);
	 if (proc == NULL)
	 {
		ereport(ERROR,
			(errmsg("PID %d is not a PostgreSQL server process", pid)));
         }
	 elog(DEBUG5, "pgls_stop pid=%d is valid", pid);

	 PG_RETURN_BOOL(pgls_stop_internal(pid));

}
/*
 *
 * pgls_vacuum: remove backends that have exited and backends that have stopped logging.
 *
 */

static void pgls_vacuum()
{
	int i;
	PGPROC	*proc;
	int j;

	elog(DEBUG5, "pgls_vacuum entry");

	LWLockAcquire(pgls->lock, LW_EXCLUSIVE);

        for (i=0; i < pgls->current_proc_num; i++)
	{
	 	proc = BackendPidGetProc(pgls->procs[i].pid);
		if (proc == NULL)
		{
			pgls->procs[i].status = pgls_none;
		}
		
	}
	
	/*
 	 * we don't store history of logging start and stop requests
 	 */		
		
        for (i=0; i < pgls->current_proc_num; i++)
	{
		if (pgls->procs[i].status == pgls_none 
                                     ||
                    pgls->procs[i].status == pgls_stopped)
		{
			elog(LOG, "pg_log_statements: removed pid=%d", pgls->procs[i].pid);
			for (j=i; j < pgls->current_proc_num;j++)
			{
				pgls->procs[j].pid = pgls->procs[j+1].pid;
				pgls->procs[j].status = pgls->procs[j+1].status;
			}		
			pgls->current_proc_num--;
		}
		
	}
	
	LWLockRelease(pgls->lock);

	elog(DEBUG5, "pgls_vacuum exit");

}

Datum pgls_state(PG_FUNCTION_ARGS)
{
	
 	return (pgls_state_internal(fcinfo));	
}

static Datum pgls_state_internal(FunctionCallInfo fcinfo)
{
	ReturnSetInfo 	*rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	bool		randomAccess;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	AttInMetadata	 *attinmeta;
	MemoryContext 	oldcontext;
	int 		i;

	/* The tupdesc and tuplestore must be created in ecxt_per_query_memory */
	oldcontext = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);
#if PG_VERSION_NUM <= 120000
	tupdesc = CreateTemplateTupleDesc(2, false);
#else
	tupdesc = CreateTemplateTupleDesc(2);
#endif
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "pid",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "status",
					   TEXTOID, -1, 0);

	randomAccess = (rsinfo->allowedModes & SFRM_Materialize_Random) != 0;
	tupstore = tuplestore_begin_heap(randomAccess, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	attinmeta = TupleDescGetAttInMetadata(tupdesc);

	LWLockAcquire(pgls->lock, LW_SHARED);

	for (i=0; i < pgls->current_proc_num; i++)
	{
		char 		*values[2];
		HeapTuple	tuple;
		char		buf_v1[10];
		char		buf_v2[30];


		snprintf(buf_v1, sizeof(buf_v1), "%d", pgls->procs[i].pid);
		values[0] = buf_v1;
		switch (pgls->procs[i].status)
		{

			case pgls_none:
				strcpy(buf_v2, "none");
				values[1]=buf_v2;
				break;

			case pgls_to_start:
				strcpy(buf_v2, "logging to start");
				values[1]=buf_v2;
				break;

			case pgls_to_stop:
				strcpy(buf_v2, "logging to stop");
				values[1]=buf_v2;
				break;

			case pgls_started:
				strcpy(buf_v2, "logging started");
				values[1]=buf_v2;
				break;

			case pgls_stopped:
				strcpy(buf_v2, "logging stopped");
				values[1]=buf_v2;
				break;

			default:
				strcpy(buf_v2, "ERROR: unexpected value");
				values[1]=buf_v2;
				break;
		}			

		tuple = BuildTupleFromCStrings(attinmeta, values);
	
		tuplestore_puttuple(tupstore, tuple);

	}

	LWLockRelease(pgls->lock);

	return (Datum)0;	

}


static void pgls_auth_debug(Port *port)
{
       if (port->remote_host != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: remote_host=%s", port->remote_host);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: remote_host=NULL");

       if (port->remote_hostname != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: remote_hostname=%s", port->remote_hostname);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: remote_hostname=NULL");

       if (port->user_name != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: user_name=%s", port->user_name);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: user_name=NULL");

       if (port->application_name != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: port->application_name=%s", port->application_name);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: port->application_name=NULL");

       if (MyProcPort->remote_host != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: MyProcPort->remote_host=%s", MyProcPort->remote_host);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: MyProcPort->remote_host=NULL");

       if (MyProcPort->remote_hostname != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: MyProcPort->remote_hostname=%s", MyProcPort->remote_hostname);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: MyProcPort->remote_hostname=NULL");


       if (MyProcPort->application_name != NULL)
               elog(LOG, "pg_log_statements: pgls_auth_debug: MyProcPort->application_name=%s", MyProcPort->application_name);
       else
               elog(LOG, "pg_log_statements: pgls_auth_debug: MyProcPort->application_name=NULL");

}

static void pgls_auth(Port *port, int status)
{

	int	 i;
	bool	found = false; 

        /*	
	 * char		remote_host[NI_MAXHOST];
	 * char		remote_port[NI_MAXSERV];
	 * int		ret;
	 */

       if (pgls->debug == true)
       	       pgls_auth_debug(port);

	if (next_client_auth_hook) 
               (*next_client_auth_hook) (port, status); 
	if (status != STATUS_OK) return;

	LWLockAcquire(pgls->lock, LW_EXCLUSIVE);

	for (i=0; i < pgls->current_filter_num && found == false ; i++)
	{
		if ( 
                      (pgls->filters[i].type == pgls_application_name 
                       && strstr(MyProcPort->application_name, pgls->filters[i].filter) != NULL)
                                              ||
                      (pgls->filters[i].type == pgls_hostname
		       && MyProcPort->remote_hostname != NULL 
                       && strcmp(MyProcPort->remote_hostname, pgls->filters[i].filter) == 0)
                                              ||
                      (pgls->filters[i].type == pgls_ip_address
		       && MyProcPort->remote_host != NULL 
                       && strcmp(MyProcPort->remote_host, pgls->filters[i].filter) == 0)
                                              ||
                      (pgls->filters[i].type == pgls_user_name
		       && MyProcPort->user_name != NULL 
                       && strcmp(MyProcPort->user_name, pgls->filters[i].filter) == 0)
                                              ||
                      (pgls->filters[i].type == pgls_database_name
		       && MyProcPort->database_name != NULL 
                       && strcmp(MyProcPort->database_name, pgls->filters[i].filter) == 0)
                   )
		{
			/*
			 * use PGC_S_DYNAMIC_DEFAULT instead of PGC_S_CLIENT to avoid
			 * TRAP: failed Assert("OidIsValid(CurrentUserId)"), File: "miscinit.c"
			 * because default value of CurrentUserId in miscinit.c is set to InvalidOid
			 */
			found = true;
       			SetConfigOption("log_statement", "all", PGC_SUSET, PGC_S_DYNAMIC_DEFAULT);
		        elog(LOG, "pg_log_statements: pgls_auth: pg_log_statement=all for %d", MyProcPid);
			pgls_add_backend(MyProcPid, pgls_started);
		}

	}

	LWLockRelease(pgls->lock);

}


/*
 *   
 *   pgls_stop_filter_internal
 *
 *  filter will be applied only to *new* backend (existing backends are *not* processed:
 *  behavior is different from logging request using process identifier)
 *   
 */
static bool pgls_stop_filter_internal(char *filter_name, char *filter_value)
{
	int 			i;
	bool 			found = false;
	int 			j;
	pgls_filter_type	filter_type;

	if (strcmp(filter_name,"application_name") == 0)
		filter_type = pgls_application_name;
	else if (strcmp(filter_name, "hostname") == 0)
		filter_type = pgls_hostname;
	else if (strcmp(filter_name, "ip_address") == 0)
		filter_type = pgls_ip_address;
	else if (strcmp(filter_name, "user_name") == 0)
		filter_type = pgls_user_name;
	else if (strcmp(filter_name, "database_name") == 0)
		filter_type = pgls_database_name;
	else	
		ereport(ERROR, (errmsg("Unkown filter=%s", filter_name)));

	LWLockAcquire(pgls->lock, LW_EXCLUSIVE);

	for (i = 0; i < pgls->current_filter_num && found == false; i++)
	{
		if (pgls->filters[i].type == filter_type 
                                           && 
                    strcmp(pgls->filters[i].filter, filter_value) == 0)
			found = true;
	}	
	if (found == false)
	{
		LWLockRelease(pgls->lock);
		ereport(ERROR, (errmsg("Filter=%s value=%s not found", filter_name, filter_value)));
	}

	/* only 1 filter to remove */
        for (j = i-1; j < pgls->current_filter_num; j++)
        {
		pgls->filters[j].type = pgls->filters[j+1].type;	
		strcpy(pgls->filters[j].filter, pgls->filters[j+1].filter);
        }
        pgls->current_filter_num--;

        elog(LOG, "pg_log_statements: removed filter=%s value=%s", filter_name, filter_value);

	LWLockRelease(pgls->lock);
	return true;
}

Datum pgls_stop_filter(PG_FUNCTION_ARGS)
{
         char  *filter_name;
         char  *filter_value;

         filter_name = PG_GETARG_CSTRING(0);
         filter_value = PG_GETARG_CSTRING(1);
         elog(LOG, "pgls_stop_filter filter=%s value=%s", filter_name, filter_value);

         PG_RETURN_BOOL(pgls_stop_filter_internal(filter_name, filter_value));
}

/*
 *  
 *  pgls_start_filter_internal
 *
 *  filter will be applied only to *new* backend (existing backends are *not* processed:
 *  behavior is different from logging request using process identifier)
 *  
 */
static bool pgls_start_filter_internal(char *filter_name, char *filter_value)
{
	bool			found = false;
	int			i;
	pgls_filter_type	filter_type;

	if (strcmp(filter_name,"application_name") == 0)
		filter_type = pgls_application_name;
	else if (strcmp(filter_name, "hostname") == 0)
		filter_type = pgls_hostname;
	else if (strcmp(filter_name, "ip_address") == 0)
		filter_type = pgls_ip_address;
	else if (strcmp(filter_name, "user_name") == 0)
		filter_type = pgls_user_name;
	else if (strcmp(filter_name, "database_name") == 0)
		filter_type = pgls_database_name;
	else	
		ereport(ERROR, (errmsg("Unkown filter: %s", filter_name)));

	LWLockAcquire(pgls->lock, LW_EXCLUSIVE);
		
	if (pgls->current_filter_num == PGLS_MFN)
	{
		LWLockRelease(pgls->lock);
		ereport(ERROR, (errmsg("Maximum filter numbers is reached %d", pgls->current_filter_num)));
	}

	if (strlen(filter_value) > PGLS_MFL)
	{
		LWLockRelease(pgls->lock);
		ereport(ERROR, (errmsg("Filter length %zu is greater than %d", strlen(application_name), PGLS_MFL)));
	}

	/* search if filter already exist ... */

	for (i = 0; i < pgls->current_filter_num && found == false; i++)
	{
		if (pgls->filters[i].type == filter_type && strcmp(pgls->filters[i].filter, filter_value) == 0)
			found = true;
	}	
	if (found == true)
	{
		LWLockRelease(pgls->lock);
		ereport(ERROR, (errmsg("Filter %s already exists", application_name)));
	}		

	pgls->filters[pgls->current_filter_num].type = filter_type;
	strcpy(pgls->filters[pgls->current_filter_num].filter, filter_value);
	pgls->current_filter_num++;

	LWLockRelease(pgls->lock);

	return true;
}

Datum pgls_start_filter(PG_FUNCTION_ARGS)
{
         char  *filter_name;
         char  *filter_value;

         filter_name = PG_GETARG_CSTRING(0);
         filter_value = PG_GETARG_CSTRING(1);
         elog(LOG, "pgls_start_app filter=%s value=%s", filter_name, filter_value);

         PG_RETURN_BOOL(pgls_start_filter_internal(filter_name, filter_value));
}

Datum pgls_conf(PG_FUNCTION_ARGS)
{

        return (pgls_conf_internal(fcinfo));
}


static Datum pgls_conf_internal(FunctionCallInfo fcinfo)
{
	ReturnSetInfo 	*rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	bool		randomAccess;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	AttInMetadata	 *attinmeta;
	MemoryContext 	oldcontext;
	int 		i;

	/* The tupdesc and tuplestore must be created in ecxt_per_query_memory */
	oldcontext = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);
#if PG_VERSION_NUM <= 120000
	tupdesc = CreateTemplateTupleDesc(2, false);
#else
	tupdesc = CreateTemplateTupleDesc(2);
#endif
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "filter type", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "filter value", TEXTOID, -1, 0);

	randomAccess = (rsinfo->allowedModes & SFRM_Materialize_Random) != 0;
	tupstore = tuplestore_begin_heap(randomAccess, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	attinmeta = TupleDescGetAttInMetadata(tupdesc);

	LWLockAcquire(pgls->lock, LW_SHARED);

	for (i=0; i < pgls->current_filter_num; i++)
	{
		char 		*values[2];
		HeapTuple	tuple;
		char		buf_v1[25];
		char		buf_v2[25];


		switch(pgls->filters[i].type)
		{
			case pgls_application_name:
				strcpy(buf_v1, "application name");
				values[0]=buf_v1;
				break;
			case pgls_hostname:
				strcpy(buf_v1, "hostname");
				values[0]=buf_v1;
				break;
			case pgls_ip_address:
				strcpy(buf_v1, "ip address");
				values[0]=buf_v1;
				break;
			case pgls_user_name:
				strcpy(buf_v1, "user_name");
				values[0]=buf_v1;
				break;
			case pgls_database_name:
				strcpy(buf_v1, "database_name");
				values[0]=buf_v1;
				break;
			default:
				strcpy(buf_v1, "ERROR: unexpected value");
				values[0]=buf_v1;
				break;
		}

		snprintf(buf_v2, sizeof(buf_v2), "%s", pgls->filters[i].filter);
		values[1] = buf_v2;

		tuple = BuildTupleFromCStrings(attinmeta, values);
	
		tuplestore_puttuple(tupstore, tuple);

	}

	LWLockRelease(pgls->lock);

	return (Datum)0;	

}

static bool pgls_start_debug_internal()
{
	/* no lock */

	pgls->debug = true;	
        elog(LOG, "pg_log_statements: pgls_start_debug");

	return true;
}

Datum pgls_start_debug(PG_FUNCTION_ARGS)
{

        return (pgls_start_debug_internal(fcinfo));
}
static bool pgls_stop_debug_internal()
{
	/* no lock */

	pgls->debug = false;	
        elog(LOG, "pg_log_statements: pgls_stop_debug");

	return true;
}

Datum pgls_stop_debug(PG_FUNCTION_ARGS)
{

        return (pgls_stop_debug_internal(fcinfo));
}
