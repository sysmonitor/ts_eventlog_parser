// Trusec Detect Eventlog Parser
// www.truesec.se
// Based on code from https://docs.microsoft.com/en-us/windows/desktop/EventLog/querying-for-event-source-messages
// Can work with both live logs and logs copied from another system

#include <windows.h>
#include <Shlwapi.h>
#include <stdio.h>

#pragma comment(lib, "shlwapi.lib")

#define MAX_TIMESTAMP_LEN       23 + 1   // yyyy-mm-dd hh:mm:ss.mmm
#define MAX_RECORD_BUFFER_SIZE  0x10000  // 64K

CONST LPWSTR pEventTypeNames[] = { L"Error", L"Warning", L"Informational", L"Audit Success", L"Audit Failure" };
DWORD nEvents = 0;
BOOL bNumNotExceeded = TRUE, bCSVOutput = FALSE, bUTC = FALSE;
wchar_t fields[50][8192];
wchar_t szSource[MAX_PATH], szComputerName[MAX_PATH];

VOID ShowErrorMessage(LPWSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and clean up
	wprintf(L"\n%s error %d: %s", lpszFunction, dw, (LPWSTR)lpMsgBuf);

	LocalFree(lpMsgBuf);
}

VOID GetEventMessage(DWORD dwEventID, wchar_t *szBuf) // Hardcode some of the most usual messages for forensic investigations
{
	switch (dwEventID)
	{
	case 4624:
		wcscpy_s(szBuf, MAX_PATH, L"An account was successfully logged on"); // Security
		break;
	case 1102:
		wcscpy_s(szBuf, MAX_PATH, L"The audit log was cleared"); // Security
		break;
	case 4625:
		wcscpy_s(szBuf, MAX_PATH, L"An account failed to log on"); // Security
		break;
	case 4648:
		wcscpy_s(szBuf, MAX_PATH, L"A logon was attempted using explicit credentials"); // Security
		break;
	case 4661:
		wcscpy_s(szBuf, MAX_PATH, L"A handle to an object was requested"); // Security
		break;
	case 4662:
		wcscpy_s(szBuf, MAX_PATH, L"An operation was performed on an object"); // Security
		break;
	case 4663:
		wcscpy_s(szBuf, MAX_PATH, L"An attempt was made to access an object"); // Security
		break;
	case 4672:
		wcscpy_s(szBuf, MAX_PATH, L"Special privileges assigned to new logon"); // Security
		break;
	case 4688:
		wcscpy_s(szBuf, MAX_PATH, L"A new process has been created"); // Security
		break;
	case 4698:
		wcscpy_s(szBuf, MAX_PATH, L"A scheduled task was created"); // Security
		break;
	case 4699:
		wcscpy_s(szBuf, MAX_PATH, L"A scheduled task was deleted"); // Security
		break;
	case 4702:
		wcscpy_s(szBuf, MAX_PATH, L"A scheduled task was updated"); // Security
		break;
	case 4720:
		wcscpy_s(szBuf, MAX_PATH, L"A user account was created"); // Security
		break;
	case 4722:
		wcscpy_s(szBuf, MAX_PATH, L"A user account was enabled"); // Security
		break;
	case 4725:
		wcscpy_s(szBuf, MAX_PATH, L"A user account was disabled"); // Security
		break;
	case 4728:
		wcscpy_s(szBuf, MAX_PATH, L"A member was added to a security-enabled global group"); // Security
		break;
	case 4738:
		wcscpy_s(szBuf, MAX_PATH, L"A user account was changed"); // Security
		break;
	case 4741:
		wcscpy_s(szBuf, MAX_PATH, L"A computer account was created"); // Security
		break;
	case 4776:
		wcscpy_s(szBuf, MAX_PATH, L"The domain controller attempted to validate the credentials for an account"); // Security
		break;
	case 5001:
		wcscpy_s(szBuf, MAX_PATH, L"Windows Defender Real-Time Protection was disabled");
		break;
	case 5007:
		wcscpy_s(szBuf, MAX_PATH, L"Windows Defender Configuration has changed");
		break;
	case 1116:
		wcscpy_s(szBuf, MAX_PATH, L"Windows Defender has detected malware or other potentially unwanted software");
		break;
	case 5140:
		wcscpy_s(szBuf, MAX_PATH, L"A network share object was accessed"); // Security
		break;
	case 5142:
		wcscpy_s(szBuf, MAX_PATH, L"A network share object was added"); // Security
		break;
	case 5145:
		wcscpy_s(szBuf, MAX_PATH, L"A network share object was checked to see whether client can be granted desired access"); // Security
		break;
	case 5156:
		wcscpy_s(szBuf, MAX_PATH, L"The Windows Filtering Platform has allowed a connection"); // Security
		break;
	case 5158:
		wcscpy_s(szBuf, MAX_PATH, L"The Windows Filtering Platform has permitted a bind to a local port"); // Security
		break;
	case 104:
		wcscpy_s(szBuf, MAX_PATH, L"The System log file was cleared"); // System
		break;
	case 7036:
		wcscpy_s(szBuf, MAX_PATH, L"The <name of service> entered the running state"); // System
		break;
	case 7040:
		wcscpy_s(szBuf, MAX_PATH, L"The start type of the IPSEC Services service was changed from disabled to auto start"); // System
		break;
	case 7045:
		wcscpy_s(szBuf, MAX_PATH, L"A service was installed in the system"); // System
		break;
	case 10028:
		wcscpy_s(szBuf, MAX_PATH, L"DCOM was unable to communicate"); // System
		break;
	case 21:
		if (!wcscmp(szSource, L"Microsoft-Windows-TerminalServices-RemoteConnectionManager"))
			wcscpy_s(szBuf, MAX_PATH, L"RDP: Session logon"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		else if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"WmiEventConsumerToFilter activity detected"); // Sysmon
		break;
	case 22:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: Shell start"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 23:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: Session logoff succeeded"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 24:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: Session has been disconnected"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 258:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: Listener RDP-Tcp has started listening"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 261:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: Listener RDP-Tcpreceived a connection"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 1136:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: RD Session Host Server role is not installed"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 1149:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: User authentication succeeded"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 1155:
		wcscpy_s(szBuf, MAX_PATH, L"RDP: The Remote Connection Manager selected Kernel mode RDP protocol stack"); // Microsoft-Windows-TerminalServices-RemoteConnectionManager
		break;
	case 1:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Process creation");
		break;
	case 2:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"A process changed a file creation time");
		break;
	case 3:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Network connection");
		break;
	case 4:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Sysmon service state changed");
		break;
	case 5:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Process terminated");
		break;
	case 6:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Driver loaded");
		break;
	case 7:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Image loaded");
		break;
	case 8:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"CreateRemoteThread");
		break;
	case 9:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Raw Access Read");
		break;
	case 10:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Process Access");
		break;
	case 11:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"File Create");
		break;
	case 12:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"RegistryEvent(Object create and delete)");
		break;
	case 13:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"RegistryEvent(Value Set)");
		break;
	case 14:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"RegistryEvent(Key and Value Rename)");
		break;
	case 15:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"FileCreateStreamHash");
		break;
	case 16:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Sysmon config state changed");
		break;
	case 17:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Pipe created");
		break;
	case 18:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"Pipe connected");
		break;
	case 19:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"WmiEventFilter activity detected");
		break;
	case 20:
		if (!wcscmp(szSource, L"Microsoft-Windows-Sysmon"))
			wcscpy_s(szBuf, MAX_PATH, L"WmiEventConsumer activity detected");
		break;
	default:
		wcscpy_s(szBuf, MAX_PATH, L" ");
		break;
	}

	return;
}

void GetTimestamp(const DWORD Time, wchar_t *DisplayString)
{
	ULONGLONG ullTimeStamp = 0;
	ULONGLONG SecsTo1970 = 116444736000000000;
	SYSTEMTIME st, stLocal;
	FILETIME ft;

	ullTimeStamp = Int32x32To64(Time, 10000000) + SecsTo1970;
	ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

	FileTimeToSystemTime(&ft, &st);
	SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);
	if (bUTC)
		swprintf_s(DisplayString, MAX_TIMESTAMP_LEN, L"%04d-%02d-%02dT%02d:%02d:%02dZ", st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond);
	else
		swprintf_s(DisplayString, MAX_TIMESTAMP_LEN, L"%04d-%02d-%02d %02d:%02d:%02d", stLocal.wYear, stLocal.wMonth, stLocal.wDay,
			stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
}

DWORD GetEventTypeName(DWORD EventType)
{
	DWORD index = 0;

	switch (EventType)
	{
	case EVENTLOG_ERROR_TYPE:
		index = 0;
		break;
	case EVENTLOG_WARNING_TYPE:
		index = 1;
		break;
	case EVENTLOG_INFORMATION_TYPE:
		index = 2;
		break;
	case EVENTLOG_AUDIT_SUCCESS:
		index = 3;
		break;
	case EVENTLOG_AUDIT_FAILURE:
		index = 4;
		break;
	}

	return index;
}

DWORD DumpRecordsInBuffer(PBYTE pBuffer, DWORD dwBytesRead, wchar_t *szProviderName, BOOL bFilterID,
	DWORD dwID, BOOL bFilterType, DWORD dwType, wchar_t *szExpr, DWORD dwNum)
{
	DWORD status = ERROR_SUCCESS, dwEventID, dwStrings, dwSourceLen;
	PBYTE pRecord = pBuffer;
	PBYTE pEndOfRecords = pBuffer + dwBytesRead;
	LPWSTR pMessage = NULL;
	LPWSTR pFinalMessage = NULL;
	wchar_t TimeStamp[MAX_TIMESTAMP_LEN + 1];
	wchar_t szEventMessage[MAX_PATH];
	wchar_t string_data[MAX_RECORD_BUFFER_SIZE];
	BOOL bShowEvent = FALSE, bTypeFound = FALSE, bEventIDFound = FALSE, bExprFound = FALSE;

	while (pRecord < pEndOfRecords)
	{
		bShowEvent = FALSE;
		bTypeFound = FALSE;
		bEventIDFound = FALSE;
		bExprFound = FALSE;

		dwStrings = ((PEVENTLOGRECORD)pRecord)->NumStrings;
		if (dwStrings == 0 || dwStrings > 50)
			goto end;

		if (bFilterType && GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType) == dwType)
			bTypeFound = TRUE;
		else if (!bFilterType)
			bTypeFound = TRUE;

		dwEventID = ((PEVENTLOGRECORD)pRecord)->EventID & 0xFFFF;

		if (bFilterID && dwEventID == dwID)
			bEventIDFound = TRUE;
		else if (!bFilterID)
			bEventIDFound = TRUE;

		// Populate szSource and szComputerName
		wcscpy_s(szSource, MAX_PATH, (wchar_t*)((LPBYTE)pRecord + sizeof(EVENTLOGRECORD)));
		dwSourceLen = (DWORD)wcslen(szSource);
		wcscpy_s(szComputerName, MAX_PATH, (wchar_t*)((LPBYTE)pRecord + sizeof(EVENTLOGRECORD) + 2 * dwSourceLen + 2));

		wcscpy_s(szEventMessage, MAX_PATH, L"");
		GetEventMessage(dwEventID, szEventMessage);
		memset(TimeStamp, 0, sizeof(TimeStamp));
		GetTimestamp(((PEVENTLOGRECORD)pRecord)->TimeGenerated, TimeStamp);

		// Get string data
		memset(string_data, 0, sizeof(string_data));
		memcpy(string_data, (LPWSTR)(pRecord + ((PEVENTLOGRECORD)pRecord)->StringOffset), ((PEVENTLOGRECORD)pRecord)->Length);

		int i = 0, j = 0, k = 0;

		// loop over data, if data[i] = '\0'
		memset(fields, 0, sizeof(fields));

		for (;;)
		{
			fields[i][j] = string_data[k];

			if (fields[i][j] == '\0')
			{
				i++;
				if (i == dwStrings)
					break;

				j = 0;
			}
			else
			{
				j++;
				if (j == 8191)
					break;
			}
			k++;
			if (k == MAX_RECORD_BUFFER_SIZE)
				break;
		}

		if (szExpr != NULL)
		{
			for (i = 0; i < (int)dwStrings; i++)
			{
				if (StrStrIW(fields[i], szExpr))
					bExprFound = TRUE;
			}
		}
		else if (szExpr == NULL)
			bExprFound = TRUE;

		if (dwNum > 0 && nEvents >= dwNum)
			bNumNotExceeded = FALSE;

		bShowEvent = bTypeFound && bEventIDFound && bExprFound && bNumNotExceeded;

		if (bShowEvent)
		{
			if (bCSVOutput)
			{
				wprintf(L"%s,%d,%s,%s,%s", TimeStamp, ((PEVENTLOGRECORD)pRecord)->EventID & 0xFFFF,
					pEventTypeNames[GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType)],
					szSource, szComputerName);

				for (i = 0; i < (int)dwStrings; i++)
				{
					if (i == (int)dwStrings - 1)
						wprintf(L"%s", fields[i]);
					else
						wprintf(L"%s,", fields[i]);
				}

				wprintf(L"\n");
			}
			else
			{
				wprintf(L"\nTime stamp: %s", TimeStamp);
				wprintf(L"\nRecord number: %lu", ((PEVENTLOGRECORD)pRecord)->RecordNumber);
				wprintf(L"\nEvent ID: %d %s", ((PEVENTLOGRECORD)pRecord)->EventID & 0xFFFF, szEventMessage);
				wprintf(L"\nEvent type: %d (%s)", GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType),
					pEventTypeNames[GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType)]);
				wprintf(L"\nSource: %s", szSource);
				wprintf(L"\nComputerName: %s", szComputerName);

				for (i = 0; i < (int)dwStrings; i++)
					wprintf(L"\nstring[%d]=%s", i, fields[i]);

				wprintf(L"\n");
			}

			nEvents++;
		}

	end:

		pRecord += ((PEVENTLOGRECORD)pRecord)->Length;
	}

	return status;
}

void print_usage()
{
	wprintf(L"\nTrusec Detect EventLog Parser: display and parse entries from event logs, locally or remotely, from live logs or logfiles on disk.\n");
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
}

void print_event_list()
{
	wprintf(L"   Security Log:\n\
		1102: The audit log was cleared \n\
		4624: An account was successfully logged on \n\
		4625: An account failed to log on\n\
		4662: An operation was performed on an object\n\
		4663: An attempt was made to access an object\n\
		4672: Special privileges assigned to new logon\n\
		4688: A new process has been created\n\
		4698: A scheduled task was created\n\
		4699: A scheduled task was deleted\n\
		4702: A scheduled task was updated\n\
		4720: A user account was created\n\
		4722: A user account was enabled\n\
		4725: A user account was disabled\n\
		4728: A member was added to a security-enabled global group\n\
		4738: A user account was changed\n\
		4741: A computer account was created\n\
		4776: The domain controller attempted to validate the credentials for an account\n\
		5140: A network share object was accessed\n\
		5156: The Windows Filtering Platform has allowed a connection\n\
   System log:\n\
		 104: The System log file was cleared.\n\
		7036: The <name of service> entered the running state\n\
		7040: The start type of the IPSEC Services service was changed from disabled to auto start\n\
		7045: A service was installed in the system\n\
		10028: DCOM was unable to communicate\n\
   PowerShell:\n\
		600: Provider 'xx' was started - detailed information about Powershell on later Windows versions\n\
		4104 : Records the script block contents, but only the first time it is executed in an attempt to reduce log volume\n\
   WMI-Activity:\n\
		5857: Provider Loading\n\
		5858: Errors\n\
		5860: Temporary WMI Events\n\
		5861: Permanent WMI Events(persistence)\n\
   Windows Defender:\n\
		5001: Windows Defender Real-Time Protection was disabled.\n\
		5007: Windows Defender Configuration has changed.\n\
		1116: Windows Defender has detected malware or other potentially unwanted software.\n\
   Terminal Services:\n\
		1149: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational\n\
		21, 22: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\n\
   Windows Firewall : \n\
		2004: A rule has been added to the Windows Firewall exception list.\n\
   Device Guard, show apps in the not-alloweed-list that tried to run\n\
	Audit mode(will let all apps run):\n\
		3076: Microsoft-Windows-CodeIntegrity/Operational\n\
	Enforced mode(blocks non-allowed apps):\n\
		3077: Microsoft-Windows-CodeIntegrity/Operational\n\
   Sysmon Events:\n\
		1: Process creation\n\
		2: A process changed a file creation time\n\
		3: Network connection\n\
		4: Sysmon service state changed\n\
		5: Process terminated\n\
		6: Driver loaded\n\
		7: Image loaded\n\
		8: CreateRemoteThread\n\
		9: RawAccessRead\n\
		10: ProcessAccess\n\
		11: FileCreate\n\
		12: RegistryEvent(Object create and delete)\n\
		13: RegistryEvent(Value Set)\n\
		14: RegistryEvent(Key and Value Rename)\n\
		15: FileCreateStreamHash\n\
		16: Sysmon config state changed\n\
		17: Pipe created\n\
		18: Pipe connected\n\
		19: WmiEventFilter activity detected\n\
		20: WmiEventConsumer activity detected\n\
		21: WmiEventConsumerToFilter activity detected\n\
		225: Error\n");
}

void wmain(int argc, wchar_t **argv)
{
	HANDLE hEventLog = NULL;
	int i;
	DWORD status = ERROR_SUCCESS;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0, dwEventID = 0, dwType;
	DWORD dwMinimumBytesToRead = 0, dwNum = 0;
	PBYTE pBuffer = NULL;
	PBYTE pTemp = NULL;
	wchar_t *szLogName = NULL, *szHost = NULL, *szExpr = NULL;
	BOOL bLogFile = FALSE, bLogName = FALSE, bFilterType = FALSE;
	BOOL bFilterEventID = FALSE;

	if (argc == 2 && !_wcsicmp(argv[1], L"-p"))
	{
		print_event_list();
		return;
	}

	if (argc == 1 || (argc == 2 && !_wcsicmp(argv[1], L"-h")))
	{
		print_usage();
		return;
	}

	// parse args
	for (i = 1; i < argc; i++)
	{
		if (!_wcsicmp(argv[i], L"-c"))
		{
			bCSVOutput = TRUE;
		}
		if (!_wcsicmp(argv[i], L"-u"))
		{
			bUTC = TRUE;
		}
		if (!wcscmp(argv[i], L"-l"))
		{
			if (argv[i + 1] != NULL)
			{
				szLogName = argv[i + 1];
				bLogFile = TRUE;
			}
			else
			{
				wprintf(L"\nNeed to provide a logfile name");
				return;
			}
		}
		if (!wcscmp(argv[i], L"-L"))
		{
			if (argv[i + 1] != NULL)
			{
				szLogName = argv[i + 1];
				bLogName = TRUE;
			}
			else
			{
				wprintf(L"\nNeed to provide a logname");
				return;
			}
		}
		if (!_wcsicmp(argv[i], L"-s"))
		{
			if (argv[i + 1] != NULL)
				szHost = argv[i + 1];
			else
			{
				wprintf(L"\nNeed to provide a host");
				return;
			}

		}
		if (!_wcsicmp(argv[i], L"-i")) // filter on EventID
		{
			if (argv[i + 1] != NULL)
			{
				dwEventID = _wtoi(argv[i + 1]);
				bFilterEventID = TRUE;
			}
			else
			{
				wprintf(L"\nNeed to provide an EventID");
				return;
			}
		}
		if (!_wcsicmp(argv[i], L"-t")) // filter on EventType
		{
			if (argv[i + 1] != NULL)
			{
				dwType = _wtoi(argv[i + 1]);
				bFilterType = TRUE;
			}
			else
			{
				wprintf(L"\nNeed to provide a type");
				return;
			}
		}
		if (!_wcsicmp(argv[i], L"-n")) // only show num entries
		{
			if (argv[i + 1] != NULL)
			{
				dwNum = _wtoi(argv[i + 1]);
			}
			else
			{
				wprintf(L"\nNeed to provide a number");
				return;
			}
		}
		if (!_wcsicmp(argv[i], L"-e")) // search stuff
		{
			if (argv[i + 1] != NULL)
				szExpr = argv[i + 1];
			else
			{
				wprintf(L"\nNeed to provide an expression");
				return;
			}
		}
	}

	if (!(bLogFile || bLogName))
	{
		wprintf(L"\nNeed to provide a logname or log filename");
		return;
	}

	if (bLogFile)
		hEventLog = OpenBackupEventLogW(szHost, szLogName);
	else if (bLogName)
		hEventLog = OpenEventLogW(szHost, szLogName);
	else
		goto cleanup;
	if (NULL == hEventLog)
	{
		ShowErrorMessage(L"OpenEventLogW");
		goto cleanup;
	}

	// Allocate an initial block of memory used to read event records. The number 
	// of records read into the buffer will vary depending on the size of each event.
	// The size of each event will vary based on the size of the user-defined
	// data included with each event, the number and length of insertion 
	// strings, and other data appended to the end of the event record.
	dwBytesToRead = MAX_RECORD_BUFFER_SIZE;
	pBuffer = (PBYTE)malloc(dwBytesToRead);
	if (NULL == pBuffer)
	{
		ShowErrorMessage(L"malloc");
		goto cleanup;
	}

	// Read blocks of records until you reach the end of the log or an 
	// error occurs. The records are read from newest to oldest. If the buffer
	// is not big enough to hold a complete event record, reallocate the buffer.
	while (ERROR_SUCCESS == status && bNumNotExceeded)
	{
		if (!ReadEventLogW(hEventLog,
			EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ,
			0,
			pBuffer,
			dwBytesToRead,
			&dwBytesRead,
			&dwMinimumBytesToRead))
		{
			status = GetLastError();
			if (ERROR_INSUFFICIENT_BUFFER == status)
			{
				status = ERROR_SUCCESS;

				pTemp = (PBYTE)realloc(pBuffer, dwMinimumBytesToRead);
				if (NULL == pTemp)
				{
					wprintf(L"Failed to reallocate the memory for the record buffer (%d bytes).\n", dwMinimumBytesToRead);
					goto cleanup;
				}

				pBuffer = pTemp;
				dwBytesToRead = dwMinimumBytesToRead;
			}
			else
			{
				if (ERROR_HANDLE_EOF != status)
				{
					ShowErrorMessage(L"ReadEventLogW");
					goto cleanup;
				}
			}
		}
		else
		{
			// Print the contents of each record in the buffer.
			DumpRecordsInBuffer(pBuffer, dwBytesRead, szLogName, bFilterEventID, dwEventID, bFilterType, dwType, szExpr, dwNum);
		}
	}

	if (!bCSVOutput)
		wprintf(L"\nEvents found: %d", nEvents);

cleanup:

	if (hEventLog)
		CloseEventLog(hEventLog);

	if (pBuffer)
		free(pBuffer);
}