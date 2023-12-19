

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "bdamclient.h"
#include "plugin.h"
#include "debug.h"

#define AMSERVER "127.0.0.1:1344"

static int query_sandbox( BDAMClient * client, const char * jobid, int *rstatus, const char * reportfile );
static char * status_to_output(int status, const char * threatname, int threattype);

int ScanFile(char *filename) {
    int err;
    int status, threattype;
    const char * threatname;
    int scanoptions = 0;
    INSPECTOR_PLUGIN_DEBUG("bdam client begain scan file: %s", filename);

    //scanoptions |= BDAM_SCANOPT_SANDBOX_PREFILTER;

    // Get a new client
    BDAMClient * client = BDAMClient_Create();
    char * amserver_sock = AMSERVER, * enum_pattern = 0, *sandbox_report_file = 0;

    if ( !client )
    {
        INSPECTOR_PLUGIN_ERROR("Error creating BitDefeinder client");
        return 2;
    }

    // Set options
    if ( scanoptions && (err = BDAMClient_SetOption( client, scanoptions, 1 ) ) != 0 )
    {
        INSPECTOR_PLUGIN_ERROR("Error setting scan options: %d", err);
        return 5;
    }
    INSPECTOR_PLUGIN_DEBUG("bdam client connect");

    // Connect to the remote server
    if ( (err = BDAMClient_Connect( client, amserver_sock )) != 0 )
    {
        INSPECTOR_PLUGIN_ERROR("Error connecting to server at %s: %d", amserver_sock, err);
        return 3;
    }

    INSPECTOR_PLUGIN_INFO("client begin scan filename: %s", filename);
    err = BDAMClient_ScanFile( client, filename, &status, &threattype, &threatname);
    if (err != 0) {
        INSPECTOR_PLUGIN_ERROR("Error scanning file %s: %d\n", filename, err );
        return 3;
    }
    // BDAM_THREAT_TYPE_NEEDSANDBOX means this is not detection, but means
    // the file must be scanned in Sandbox
    INSPECTOR_PLUGIN_DEBUG("status:%d", status);
    INSPECTOR_PLUGIN_DEBUG("threattype:%d", threattype);
    if (threatname)
        INSPECTOR_PLUGIN_DEBUG("threatname:%s", threatname);
    INSPECTOR_PLUGIN_INFO("SCAN result: %s", status_to_output(status, threatname, threattype));
    if ( threattype == BDAM_THREAT_TYPE_NEEDSANDBOX )
    {
        // Send the file to sandbox
        char jobid[1024], boxresult[4096];
        if ( BDAMClient_SandboxSendFile( client, filename, jobid, sizeof(jobid) ) != 0 ) {
            query_sandbox(client, jobid, &status, NULL);
        }
        if ( status == BDAM_SCANRES_CLEAN ) {
            // file is clean
        } else {
            // it is malware, and boxresult contains threat intelligence
        }
    }
    return 0;
}

static int sandbox_report_callback( void * context, const char * data, unsigned int size, unsigned int /*totalsize*/ )
{
    fwrite( data, 1, size, (FILE*) context );
  	return 0;
}

static int query_sandbox( BDAMClient * client, const char * jobid, int *rstatus, const char * reportfile )
{
    // Check the status
    int err, status;
    char boxresult[4096];
    int loop = 4;

    while ( (err = BDAMClient_SandboxQueryJob( client, jobid, &status, boxresult, sizeof(boxresult) ) ) == 0 )
    {
        if (loop-- < 0) {
            break;
        }
        if ( status == BDAM_SCANRES_INCOMPLETE )
        {
            INSPECTOR_PLUGIN_DEBUG("... still pending\n");
            sleep ( 15 );
            continue;
        }

        if ( status == BDAM_SCANRES_CLEAN )
        {
            INSPECTOR_PLUGIN_INFO("Sandbox: the content is clean\n" );
            break;
        }
        else
        {
            // Replace all | by \n in result
            char * p;

            while ( ( p = strchr( boxresult, '|') ) != 0 )
                *p = '\n';

            INSPECTOR_PLUGIN_INFO("Sandbox: the content is malware. Threat info:\n%s\n", boxresult );
            break;
        }
    }

    if (status == 0) {
        INSPECTOR_PLUGIN_ERROR("Error querying job id: %s", jobid );
        return 10;
    }

    if ( err != 0 ) {
        INSPECTOR_PLUGIN_ERROR("Error querying job id: %s, %d", jobid, err );
        return 10;
    }

    if (rstatus) {
        *rstatus = status;
    }

    // Save the sandbox report into a file if requested
    if ( reportfile )
    {
        FILE * fp = fopen( reportfile, "wb" );

        if ( !fp )
        {
            INSPECTOR_PLUGIN_ERROR("Could not write sandbox report into %s: %s", reportfile, strerror(errno));
            return 10;
        }

        err = BDAMClient_SandboxGetHtmlReportJob( client, jobid, sandbox_report_callback, fp );
        fclose( fp );

        if ( err != 0 )
        {
            INSPECTOR_PLUGIN_ERROR("Error writing sandbox report for job id: %d", err);
            return 10;
        }

        INSPECTOR_PLUGIN_INFO("Sandbox report has been writtein into file %s", reportfile );
    }

    return 0;
}

static char * status_to_output(int status, const char * threatname, int threattype)
{
    static char buf[512];
    const char * typetxt = "unknown";
    
    switch ( threattype )
    {
        case BDAM_THREAT_TYPE_VIRUS:
            typetxt = "virus";
            break;
            
        case BDAM_THREAT_TYPE_SPYWARE:
            typetxt = "spyware app";
            break;

        case BDAM_THREAT_TYPE_ADWARE:
            typetxt = "adware app";
            break;

        case BDAM_THREAT_TYPE_DIALER:
            typetxt = "dialer app";
            break;

        case BDAM_THREAT_TYPE_APP:
            typetxt = "potentially dangerous app";
            break;

        case BDAM_THREAT_TYPE_SPAM:
            typetxt = "spam email";
            break;

        case BDAM_THREAT_TYPE_BULKSPAM:
            typetxt = "bulkspam email";
            break;

        case BDAM_THREAT_TYPE_MARKETING:
            typetxt = "marketing email";
            break;

        case BDAM_THREAT_TYPE_PHISHING:
            typetxt = "phishing email";
            break;

        case BDAM_THREAT_TYPE_NEEDSANDBOX:
            typetxt = "need-to-sandbox";
            break;
    }
    
    switch ( status )
    {
        case BDAM_SCANRES_CLEAN:
            strcpy( buf, "CLEAN" );
            break;
            
        case BDAM_SCANRES_INFECTED:
            sprintf( buf, "INFECTED %s %s", typetxt, threatname ? threatname : "NULL");
            break;

        case BDAM_SCANRES_SUSPICIOUS:
            sprintf( buf, "SUSPICION %s", threatname ? threatname : "NULL");
            break;

        case BDAM_SCANRES_ENCRYPTED:
            strcpy( buf, "ENCRYPTED" );
            break;

        case BDAM_SCANRES_CORRUPTED:
            strcpy( buf, "CORRUPTED" );
            break;

        case BDAM_SCANRES_DISINFECTED:
            sprintf( buf, "DISINFECTED %s %s", typetxt, threatname ? threatname : "NULL");
            break;

        case BDAM_SCANRES_DISINFECTFAILED:
            sprintf( buf, "DISINFECTFAILED %s %s", typetxt, threatname ? threatname : "NULL");
            break;

        case BDAM_SCANRES_INCOMPLETE:
            strcpy( buf, "FAILED" );
            break;
    }
    
    return buf;
}
