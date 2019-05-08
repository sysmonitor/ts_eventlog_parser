** Truesec Eventlog parser

Windows commandline utility written in C. Tested on Windows Vista / Server 2008 and later

Syntax

\tTrusec Detect EventLog Parser: display and parse entries from event logs, locally or remotely, from live logs or logfiles on disk.\n");
	wprintf(L"\nUsage: eventlog_tool [-h] [-p] [-c] [-u] <-l <logfile> | -L <logname>> [-s <host> -i <eventID> -t <type> -e <expr> -n <num>]\n");
	wprintf(L"\n  -h            :  This help.");
	wprintf(L"\n  -p            :  Do not display any entries, but instead dump a list of interesting Event IDs.");
	wprintf(L"\n  -c            :  Comma separated output.");
	wprintf(L"\n  -u            :  Timestamps in UTC (default: localtime)");
	wprintf(L"\n  -l <logfile>  :  Event logfile. Parses an .evtx-file from disk");
	wprintf(L"\n  -L <logname>  :  Event logname. Parses an eventlog with ReadEventLog.");
	wprintf(L"\n  -s <host>     :  Hostname to get log entries from. Default: localhost.");
	wprintf(L"\n  -i <eventID>  :  Only show EventIDs matching <eventID>");
	wprintf(L"\n  -t <type>     :  Event type. Allowed are: 0 (ERROR), 1 (WARNING), 2 (INFO), 3 (SUCCESS), 4 (FAILURE)");
	wprintf(L"\n  -e <expr>     :  Only show events in which any of the strings include 'expr' (case insensitive).");
	wprintf(L"\n  -n <num>      :  Only show <num> number of events\n");
	wprintf(L"\nExample 1: eventlog_tool -l c:\\temp\\sec.evtx -i 4624\n");
	wprintf(L"\nExample 2: eventlog_tool -L Security -i 4688 -e powershell.exe\n");
	wprintf(L"\nExample 3: eventlog_tool -L \"Windows Powershell\" -i 600\n");
	wprintf(L"\nThe tool should be able to work with any exported or copied event log in .evtx-format on disk\n");
	wprintf(L"\nas well as with the normal live Application, System, Security or Windows PowerShell logs.\n");