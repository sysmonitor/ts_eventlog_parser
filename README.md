**Truesec Eventlog parser**  
  
*Windows commandline utility written in C. Tested on Windows Vista / Server 2008 and later*  
  
Trusec Detect EventLog Parser: display and parse entries from event logs, locally or remotely, from live logs or logfiles on disk.\n"); 
  
Usage: eventlog_parser [-h] [-p] [-c] [-u] <-l <logfile> | -L <logname>> [-s <host> -i <eventID> -t <type> -e <expr> -n <num>]\n");  
      
        -h            :  This help.  
        -p            :  Do not display any entries, but instead dump a list of interesting Event IDs.  
        -c            :  Comma separated output.  
        -u            :  Timestamps in UTC (default: localtime)  
        -l <logfile>  :  Event logfile. Parses an .evtx-file from disk.  
        -L <logname>  :  Event logname. Parses an eventlog with ReadEventLog.  
        -s <host>     :  Hostname to get log entries from. Default: localhost.  
        -i <eventID>  :  Only show EventIDs matching <eventID>  
        -t <type>     :  Event type. Allowed are: 0 (ERROR), 1 (WARNING), 2 (INFO), 3 (SUCCESS), 4 (FAILURE).  
        -e <expr>     :  Only show events in which any of the strings include 'expr' (case insensitive).  
        -n <num>      :  Only show <num> number of events.  
        
Example 1: eventlog_tool -l c:\\temp\\sec.evtx -i 4624  

Example 2: eventlog_tool -L Security -i 4688 -e powershell.exe  

Example 3: eventlog_tool -L \"Windows Powershell\" -i 600  

The tool should be able to work with any exported or copied event log in .evtx-format on disk as well as with the normal live Application, System, Security or Windows PowerShell logs.  
      
