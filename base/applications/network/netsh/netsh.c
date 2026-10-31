/*
 * PROJECT:    ReactOS NetSh
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    Network Shell main file
 * COPYRIGHT:  Copyright 2023 Eric Kohl <eric.kohl@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

#define COBJMACROS
#include <objbase.h>
#include <netfw.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

HMODULE g_hModule = NULL;

/* FUNCTIONS ******************************************************************/

DWORD
RunScript(
    _In_ LPCWSTR filename)
{
    WCHAR tmp_string[MAX_STRING_SIZE];
    FILE *script;
    DWORD dwError = ERROR_SUCCESS;

    /* Open the file for processing */
    script = _wfopen(filename, L"r");
    if (script == NULL)
    {
        ConResPrintf(StdErr, IDS_OPEN_FAILED, filename);
        return ERROR_FILE_NOT_FOUND;
    }

    /* Read and process the script */
    while (fgetws(tmp_string, MAX_STRING_SIZE, script) != NULL)
    {
        dwError = InterpretLine(tmp_string);
        if (dwError != ERROR_SUCCESS)
            break;
    }

    /* Close the file */
    fclose(script);

    return dwError;
}


LPWSTR
MergeStrings(
    _In_ LPWSTR pszStringArray[],
    _In_ UINT nCount)
{
    LPWSTR pszOutString = NULL;
    size_t nLength;
    UINT i;

    if ((pszStringArray == NULL) || (nCount == 0))
        return NULL;

    nLength = 0;
    for (i = 0; i < nCount; i++)
        nLength += wcslen(pszStringArray[i]);

    if (nLength > 0)
        nLength += nCount; /* Space characters and terminating zero */

    pszOutString = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nLength * sizeof(WCHAR));
    if (pszOutString == NULL)
        return NULL;

    for (i = 0; i < nCount; i++)
    {
        if (i != 0)
            wcscat(pszOutString, L" ");
        wcscat(pszOutString, pszStringArray[i]);
    }

    return pszOutString;
}


/*
 * wmain():
 * Main entry point of the application.
 */
int
wmain(
    _In_ int argc,
    _In_ const LPWSTR argv[])
{
    LPCWSTR pszScriptFileName = NULL;
    LPCWSTR pszAliasFileName = NULL;
    LPCWSTR pszContext = NULL;
    LPWSTR pszCommand = NULL;
    int index;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("wmain(%S)\n", GetCommandLineW());

    GetWmiVersionInfo();

    g_hModule = GetModuleHandle(NULL);

    /* Initialize the Console Standard Streams */
    ConInitStdStreams();

    /* FIXME: Init code goes here */
    InitAliases();
    CreateRootHelper();
    CreateRootContext();
    LoadHelpers();

    /* Process the command arguments */
    for (index = 1; index < argc; index++)
    {
        if ((_wcsicmp(argv[index], L"-?") == 0) ||
            (_wcsicmp(argv[index], L"/?") == 0) ||
            (_wcsicmp(argv[index], L"?") == 0))
        {
            /* Help option */
            ConResPuts(StdOut, IDS_APP_USAGE);
            dwError = ERROR_SUCCESS;
            goto done;
        }
        else if ((_wcsicmp(argv[index], L"-a") == 0) ||
                 (_wcsicmp(argv[index], L"/a") == 0))
        {
            /* Aliasfile option */
            if ((index + 1) < argc)
            {
                index++;
                ConPuts(StdOut, L"\nThe -a option is not implemented yet\n");
                pszAliasFileName = argv[index];
            }
            else
            {
                ConResPuts(StdOut, IDS_APP_USAGE);
                dwError = ERROR_INVALID_SYNTAX;
                goto done;
            }
        }
        else if ((_wcsicmp(argv[index], L"-c") == 0) ||
                 (_wcsicmp(argv[index], L"/c") == 0))
        {
            /* Context option */
            if ((index + 1) < argc)
            {
                index++;
                pszContext = argv[index];
            }
            else
            {
                ConResPuts(StdOut, IDS_APP_USAGE);
                dwError = ERROR_INVALID_SYNTAX;
                goto done;
            }
        }
        else if ((_wcsicmp(argv[index], L"-f") == 0) ||
                 (_wcsicmp(argv[index], L"/f") == 0))
        {
            /* File option */
            if ((index + 1) < argc)
            {
                index++;
                pszScriptFileName = argv[index];
            }
            else
            {
                ConResPuts(StdOut, IDS_APP_USAGE);
                dwError = ERROR_INVALID_SYNTAX;
                goto done;
            }
        }
        else if ((_wcsicmp(argv[index], L"-r") == 0) ||
                 (_wcsicmp(argv[index], L"/r") == 0))
        {
            /* Remote option */
            if ((index + 1) < argc)
            {
                index++;
                g_pszMachine = HeapAlloc(GetProcessHeap(), 0, (wcslen(argv[index]) + 1) * sizeof(WCHAR));
                if (g_pszMachine == NULL)
                {
                    dwError = ERROR_NOT_ENOUGH_MEMORY;
                    PrintError(g_hModule, dwError);
                    goto done;
                }

                wcscpy(g_pszMachine, argv[index]);
            }
            else
            {
                ConResPuts(StdOut, IDS_APP_USAGE);
                dwError = ERROR_INVALID_SYNTAX;
                goto done;
            }
        }
        else
        {
            if (pszScriptFileName != NULL)
            {
                ConResPuts(StdOut, IDS_APP_USAGE);
                dwError = ERROR_INVALID_SYNTAX;
                goto done;
            }
            else if (pszCommand == NULL)
            {
                pszCommand = MergeStrings((LPWSTR*)&argv[index], argc - index);
                if (pszCommand == NULL)
                {
                    dwError = ERROR_NOT_ENOUGH_MEMORY;
                    PrintError(g_hModule, dwError);
                    goto done;
                }

                break;
            }
        }
    }

    /* Run the alias file */
    if (pszAliasFileName != NULL)
    {
        dwError = RunScript(pszAliasFileName);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Set a context */
    if (pszContext)
    {
        dwError = InterpretLine((LPWSTR)pszContext);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Run a script, the command line instruction or the interactive interpeter */
    if (pszScriptFileName != NULL)
    {
        dwError = RunScript(pszScriptFileName);
    }
    else if (pszCommand != NULL)
    {
        dwError = InterpretLine(pszCommand);
    }
    else
    {
        InterpretInteractive();
    }

done:
    /* FIXME: Cleanup code goes here */
    if (g_pszMachine != NULL)
        HeapFree(GetProcessHeap(), 0, g_pszMachine);

    if (pszCommand != NULL)
        HeapFree(GetProcessHeap(), 0, pszCommand);

    CleanupContext();
    UnloadHelpers();
    DestroyAliases();

    return (dwError == ERROR_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VOID
WINAPI
FreeQuotedString(
    _In_ LPWSTR pszQuotedString)
{
    DPRINT("FreeQuotedString(%S)\n", pszQuotedString);
    HeapFree(GetProcessHeap(), 0, pszQuotedString);
}

VOID
WINAPI
FreeString(
    _In_ LPWSTR pszString)
{
    DPRINT("FreeString(%S)\n", pszString);
    LocalFree(pszString);
}

LPWSTR
WINAPI
MakeQuotedString(
    _In_ LPWSTR pszString)
{
    LPWSTR pszQuotedString;

    DPRINT("MakeQuotedString(%S)\n", pszString);

    pszQuotedString = HeapAlloc(GetProcessHeap(), 0, (wcslen(pszString) + 3) * sizeof(WCHAR));
    if (pszQuotedString == NULL)
        return NULL;

    _swprintf(pszQuotedString, L"\"%s\"", pszString);

    return pszQuotedString;
}

LPWSTR
CDECL
MakeString(
    _In_ HANDLE hModule,
    _In_ DWORD dwMsgId,
    ...)
{
    LPCWSTR pszStr;
    LPWSTR pszInBuffer, pszOutBuffer = NULL;
    DWORD dwLength;
    va_list ap;

    DPRINT("MakeString(%p %lu ...)\n", hModule, dwMsgId);

    dwLength = LoadStringW(hModule, dwMsgId, (LPWSTR)&pszStr, 0);
    if (dwLength == 0)
        return NULL;

    /* Allocate and copy the resource string, NUL-terminated */
    pszInBuffer = HeapAlloc(GetProcessHeap(), 0, (dwLength + 1) * sizeof(WCHAR));
    if (pszInBuffer == NULL)
        return NULL;
    CopyMemory(pszInBuffer, pszStr, dwLength * sizeof(WCHAR));
    pszInBuffer[dwLength] = UNICODE_NULL;

    va_start(ap, dwMsgId);
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING,
                   pszInBuffer,
                   0,
                   0,
                   (LPWSTR)&pszOutBuffer,
                   0,
                   &ap);
    va_end(ap);

    HeapFree(GetProcessHeap(), 0, pszInBuffer);

    return pszOutBuffer;
}

DWORD
WINAPI
MatchEnumTag(
    _In_ HANDLE hModule,
    _In_ LPCWSTR pwcArg,
    _In_ DWORD dwNumArg,
    _In_ const TOKEN_VALUE *pEnumTable,
    _Out_ PDWORD pdwValue)
{
    DWORD i;

    DPRINT("MatchEnumTag(%p %p %lu %p %p)\n", hModule, pwcArg, dwNumArg, pEnumTable, pdwValue);

    if ((pEnumTable == NULL) || (pdwValue == NULL))
        return ERROR_INVALID_PARAMETER;

    for (i = 0; i < dwNumArg; i++)
    {
        DPRINT("%S -- %S\n", pwcArg, pEnumTable[i].pwszToken);
        if (MatchToken(pwcArg, pEnumTable[i].pwszToken))
        {
            *pdwValue = pEnumTable[i].dwValue;
            return ERROR_SUCCESS;
        }
    }

    return ERROR_NOT_FOUND;
}

DWORD
WINAPI
MatchTagsInCmdLine(
    _In_ HANDLE hModule,
    _Inout_ LPWSTR *ppwcArguments,
    _In_ DWORD dwCurrentIndex,
    _In_ DWORD dwArgCount,
    _Inout_ TAG_TYPE *pttTags,
    _In_ DWORD dwTagCount,
    _Out_ DWORD *pdwTagType)
{
    PWSTR pszEqual;
    DWORD i, j, dwTagLength;

    DPRINT1("MatchTagsInCmdLine(%p %p %lu %lu %p %lu %p)\n",
            hModule, ppwcArguments, dwCurrentIndex, dwArgCount,
            pttTags, dwTagCount, pdwTagType);

    /* Identify tagged arguments (tag=value) */
    for (i = dwCurrentIndex; i < dwArgCount; i++)
    {
        DPRINT("Argument %lu: %S\n", i, ppwcArguments[i]);
        pdwTagType[i - dwCurrentIndex] = (DWORD)-1;

        /* Skip arguments that do not have a tag */
        pszEqual = wcschr(ppwcArguments[i], L'=');
        if (pszEqual == NULL)
            continue;

        dwTagLength = pszEqual - ppwcArguments[i];
        DPRINT("Tag length %lu\n", dwTagLength);
        DPRINT("Value length %lu\n", wcslen(pszEqual + 1));

        pdwTagType[i - dwCurrentIndex] = (DWORD)-1;
        for (j = 0; j < dwTagCount; j++)
        {
            DPRINT("Test tag %S -- %S\n", pttTags[j].pwszTag, ppwcArguments[i]);
            if ((wcslen(pttTags[j].pwszTag) == dwTagLength) &&
                (_wcsnicmp(ppwcArguments[i], pttTags[j].pwszTag, dwTagLength) == 0))
            {
                DPRINT("Found tag %S\n", pttTags[j].pwszTag);
                pttTags[j].bPresent = TRUE;
                pdwTagType[i - dwCurrentIndex] = j;

                /* Remove the tag name from the argument */
                wcscpy(ppwcArguments[i], pszEqual + 1);
                break;
            }
        }
    }

    /* Identify un-tagged arguments (value) */
    for (i = dwCurrentIndex; i < dwArgCount; i++)
    {
        if (pdwTagType[i - dwCurrentIndex] != (DWORD)-1)
            continue;

        for (j = 0; j < dwTagCount; j++)
        {
            DPRINT("Test tag %S\n", pttTags[j].pwszTag);
            if (pttTags[j].bPresent == FALSE)
            {
                DPRINT("Found tag %S\n", pttTags[j].pwszTag);
                pttTags[j].bPresent = TRUE;
                pdwTagType[i - dwCurrentIndex] = j;
                break;
            }
        }
    }

    return ERROR_SUCCESS;
}

BOOL
WINAPI
MatchToken(
    _In_ LPCWSTR pwszUserToken,
    _In_ LPCWSTR pwszCmdToken)
{
    DPRINT("MatchToken(%S %S)\n", pwszUserToken, pwszCmdToken);

    if ((pwszUserToken == NULL) || (pwszCmdToken == NULL))
        return FALSE;

    return (_wcsnicmp(pwszUserToken, pwszCmdToken, wcslen(pwszUserToken)) == 0) ? TRUE : FALSE;
}

DWORD
WINAPI 
NsGetFriendlyNameFromIfName(
    _In_ DWORD dwUnknown1,
    _In_ PWSTR pszIfName, 
    _Inout_ PWSTR pszFriendlyName,
    _Inout_ PDWORD pdwFriendlyName)
{
    UNICODE_STRING UnicodeIfName;
    GUID InterfaceGuid;
    NTSTATUS Status;
    DWORD ret;

    DPRINT("NsGetFriendlyNameFromIfName(%lx %S %p %p)\n",
           dwUnknown1, pszIfName, pszFriendlyName, pdwFriendlyName);

    RtlInitUnicodeString(&UnicodeIfName, pszIfName);
    Status = RtlGUIDFromString(&UnicodeIfName,
                               &InterfaceGuid);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlGUIDFromString failed 0x%08lx\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    ret = NhGetInterfaceNameFromDeviceGuid(&InterfaceGuid,
                                           pszFriendlyName,
                                           pdwFriendlyName,
                                           0, 0);
    if (ret != ERROR_SUCCESS)
    {
        DPRINT1("NhGetInterfaceNameFromDeviceGuid() failed %lu\n", ret);
    }

    return ret;
}

DWORD
WINAPI
NsGetIfNameFromFriendlyName(
    _In_ DWORD dwUnknown1,
    _In_ PWSTR pszFriendlyName, 
    _Inout_ PWSTR pszIfName,
    _Inout_ PDWORD pdwIfName)
{
    UNICODE_STRING UnicodeIfName;
    GUID InterfaceGuid;
    NTSTATUS Status;
    DWORD ret;

    DPRINT("NsGetIfNameFromFriendlyName(%lx %S %p %p)\n",
           dwUnknown1, pszFriendlyName, pszIfName, pdwIfName);

    ret = NhGetGuidFromInterfaceName(pszFriendlyName,
                                     &InterfaceGuid,
                                     0, 0);
    if (ret != ERROR_SUCCESS)
    {
        DPRINT1("NhGetGuidFromInterfaceName failed %lu\n", ret);
        return ret;
    }

    RtlInitUnicodeString(&UnicodeIfName, NULL);
    Status = RtlStringFromGUID(&InterfaceGuid,
                               &UnicodeIfName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlStringFromGUID failed 0x%08lx\n", Status);
        ret = RtlNtStatusToDosError(Status);
    }

    if (*pdwIfName >= UnicodeIfName.MaximumLength)
    {
        CopyMemory(pszIfName, UnicodeIfName.Buffer, UnicodeIfName.MaximumLength);
        *pdwIfName = UnicodeIfName.MaximumLength;
    }

    RtlFreeUnicodeString(&UnicodeIfName);

    return ret;
}

DWORD
WINAPI
PreprocessCommand(
    _In_ HANDLE hModule,
    _Inout_ LPWSTR *ppwcArguments,
    _In_ DWORD dwCurrentIndex,
    _In_ DWORD dwArgCount,
    _Inout_ TAG_TYPE *pttTags,
    _In_ DWORD dwTagCount,
    _In_ DWORD dwMinArgs,
    _In_ DWORD dwMaxArgs,
    _Out_ DWORD *pdwTagType)
{
    DWORD i;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("PreprocessCommand()\n");

    if ((ppwcArguments == NULL) || (pttTags == NULL) || (pdwTagType == NULL))
        return ERROR_INVALID_PARAMETER;

    if (((dwArgCount - dwCurrentIndex) < dwMinArgs) || ((dwArgCount - dwCurrentIndex) > dwMaxArgs))
        return ERROR_INVALID_SYNTAX;

    for (i = 0; i < dwTagCount; i++)
    {
        pttTags[i].bPresent = FALSE;
    }

    if ((dwArgCount - dwCurrentIndex) > 0)
    {
        dwError = MatchTagsInCmdLine(hModule,
                                     ppwcArguments,
                                     dwCurrentIndex,
                                     dwArgCount,
                                     pttTags,
                                     dwTagCount,
                                     pdwTagType);
        if (dwError != ERROR_SUCCESS)
        {
            return dwError;
        }
    }

    /* Fail, if a required tag is missing */
    for (i = 0; i < dwTagCount; i++)
    {
        if ((pttTags[i].dwRequired & NS_REQ_PRESENT) && (pttTags[i].bPresent == FALSE))
            return ERROR_INVALID_SYNTAX;
    }

    return 0;
}

typedef struct _FIREWALL_RULE_ARGUMENTS
{
    LPCWSTR Name;
    LPCWSTR Direction;
    LPCWSTR Action;
    LPCWSTR Protocol;
    LPCWSTR LocalPort;
    LPCWSTR RemotePort;
    LPCWSTR LocalAddress;
    LPCWSTR RemoteAddress;
    LPCWSTR Program;
    LPCWSTR Description;
    LPCWSTR Profile;
    LPCWSTR Enabled;
    DWORD Seen;
} FIREWALL_RULE_ARGUMENTS;

enum
{
    FW_ARG_NAME = 0x0001,
    FW_ARG_DIRECTION = 0x0002,
    FW_ARG_ACTION = 0x0004,
    FW_ARG_PROTOCOL = 0x0008,
    FW_ARG_LOCAL_PORT = 0x0010,
    FW_ARG_REMOTE_PORT = 0x0020,
    FW_ARG_LOCAL_ADDRESS = 0x0040,
    FW_ARG_REMOTE_ADDRESS = 0x0080,
    FW_ARG_PROGRAM = 0x0100,
    FW_ARG_DESCRIPTION = 0x0200,
    FW_ARG_PROFILE = 0x0400,
    FW_ARG_ENABLED = 0x0800
};

static DWORD
FirewallParseArguments(
    _Inout_ FIREWALL_RULE_ARGUMENTS *Arguments,
    _In_ LPWSTR *argv,
    _In_ DWORD CurrentIndex,
    _In_ DWORD ArgumentCount,
    _In_ BOOL Show)
{
    DWORD Index;

    ZeroMemory(Arguments, sizeof(*Arguments));
    for (Index = CurrentIndex; Index < ArgumentCount; Index++)
    {
        LPWSTR equals = wcschr(argv[Index], L'=');
        LPCWSTR key, value;
        DWORD flag;
        LPCWSTR *destination;

        if (!equals || equals == argv[Index])
            return ERROR_INVALID_SYNTAX;
        *equals = 0;
        key = argv[Index];
        value = equals + 1;
        if (!value[0])
            return ERROR_INVALID_SYNTAX;

        if (!_wcsicmp(key, L"name"))
        {
            flag = FW_ARG_NAME;
            destination = &Arguments->Name;
        }
        else if (Show)
            return ERROR_INVALID_SYNTAX;
        else if (!_wcsicmp(key, L"dir"))
        {
            flag = FW_ARG_DIRECTION;
            destination = &Arguments->Direction;
        }
        else if (!_wcsicmp(key, L"action"))
        {
            flag = FW_ARG_ACTION;
            destination = &Arguments->Action;
        }
        else if (!_wcsicmp(key, L"protocol"))
        {
            flag = FW_ARG_PROTOCOL;
            destination = &Arguments->Protocol;
        }
        else if (!_wcsicmp(key, L"localport"))
        {
            flag = FW_ARG_LOCAL_PORT;
            destination = &Arguments->LocalPort;
        }
        else if (!_wcsicmp(key, L"remoteport"))
        {
            flag = FW_ARG_REMOTE_PORT;
            destination = &Arguments->RemotePort;
        }
        else if (!_wcsicmp(key, L"localip"))
        {
            flag = FW_ARG_LOCAL_ADDRESS;
            destination = &Arguments->LocalAddress;
        }
        else if (!_wcsicmp(key, L"remoteip"))
        {
            flag = FW_ARG_REMOTE_ADDRESS;
            destination = &Arguments->RemoteAddress;
        }
        else if (!_wcsicmp(key, L"program"))
        {
            flag = FW_ARG_PROGRAM;
            destination = &Arguments->Program;
        }
        else if (!_wcsicmp(key, L"description"))
        {
            flag = FW_ARG_DESCRIPTION;
            destination = &Arguments->Description;
        }
        else if (!_wcsicmp(key, L"profile"))
        {
            flag = FW_ARG_PROFILE;
            destination = &Arguments->Profile;
        }
        else if (!_wcsicmp(key, L"enable"))
        {
            flag = FW_ARG_ENABLED;
            destination = &Arguments->Enabled;
        }
        else
            return ERROR_INVALID_SYNTAX;

        if (Arguments->Seen & flag)
            return ERROR_INVALID_SYNTAX;
        Arguments->Seen |= flag;
        *destination = value;
    }

    if (!Arguments->Name && !Show)
        return ERROR_INVALID_SYNTAX;
    if (!Show && (!Arguments->Direction || !Arguments->Action))
        return ERROR_INVALID_SYNTAX;
    return ERROR_SUCCESS;
}

static DWORD
FirewallHresultToError(HRESULT hr)
{
    if (SUCCEEDED(hr))
        return ERROR_SUCCESS;
    if (HRESULT_FACILITY(hr) == FACILITY_WIN32)
        return HRESULT_CODE(hr);
    return ERROR_GEN_FAILURE;
}

static HRESULT
FirewallSetString(
    _In_ INetFwRule *Rule,
    _In_ HRESULT (WINAPI *Setter)(INetFwRule *, BSTR),
    _In_ LPCWSTR Value)
{
    BSTR string = SysAllocString(Value);
    HRESULT hr;

    if (!string)
        return E_OUTOFMEMORY;
    hr = Setter(Rule, string);
    SysFreeString(string);
    return hr;
}

static HRESULT
FirewallGetRules(
    _Out_ INetFwPolicy2 **Policy,
    _Out_ INetFwRules **Rules)
{
    HRESULT hr;

    *Policy = NULL;
    *Rules = NULL;
    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void **)Policy);
    if (SUCCEEDED(hr))
        hr = INetFwPolicy2_get_Rules(*Policy, Rules);
    if (FAILED(hr) && *Policy)
    {
        INetFwPolicy2_Release(*Policy);
        *Policy = NULL;
    }
    return hr;
}

static HRESULT
FirewallSetRule(
    _In_ INetFwRule *Rule,
    _In_ const FIREWALL_RULE_ARGUMENTS *Arguments)
{
    HRESULT hr;
    LONG protocol = 256;
    LONG profiles = NET_FW_PROFILE2_ALL;
    VARIANT_BOOL enabled = VARIANT_TRUE;

    if (!_wcsicmp(Arguments->Direction, L"in"))
        hr = INetFwRule_put_Direction(Rule, NET_FW_RULE_DIR_IN);
    else if (!_wcsicmp(Arguments->Direction, L"out"))
        hr = INetFwRule_put_Direction(Rule, NET_FW_RULE_DIR_OUT);
    else
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    if (FAILED(hr)) return hr;

    if (!_wcsicmp(Arguments->Action, L"allow"))
        hr = INetFwRule_put_Action(Rule, NET_FW_ACTION_ALLOW);
    else if (!_wcsicmp(Arguments->Action, L"block"))
        hr = INetFwRule_put_Action(Rule, NET_FW_ACTION_BLOCK);
    else
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    if (FAILED(hr)) return hr;

    if (Arguments->Protocol)
    {
        if (!_wcsicmp(Arguments->Protocol, L"tcp"))
            protocol = 6;
        else if (!_wcsicmp(Arguments->Protocol, L"udp"))
            protocol = 17;
        else if (!_wcsicmp(Arguments->Protocol, L"any"))
            protocol = 256;
        else
        {
            WCHAR *end;
            unsigned long number = wcstoul(Arguments->Protocol, &end, 10);
            if (*end || number > 256)
                return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
            protocol = number;
        }
    }
    hr = INetFwRule_put_Protocol(Rule, protocol);
    if (FAILED(hr)) return hr;

    if (Arguments->Profile)
    {
        WCHAR *profiles_text = _wcsdup(Arguments->Profile);
        WCHAR *part, *start;

        if (!profiles_text) return E_OUTOFMEMORY;
        profiles = 0;
        start = profiles_text;
        do
        {
            part = wcschr(start, L',');
            if (part)
            {
                if (!part[1])
                {
                    free(profiles_text);
                    return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
                }
                *part = 0;
            }
            if (!start[0])
            {
                free(profiles_text);
                return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
            }
            if (!_wcsicmp(start, L"all"))
                profiles = NET_FW_PROFILE2_ALL;
            else if (!_wcsicmp(start, L"domain"))
                profiles |= NET_FW_PROFILE2_DOMAIN;
            else if (!_wcsicmp(start, L"private"))
                profiles |= NET_FW_PROFILE2_PRIVATE;
            else if (!_wcsicmp(start, L"public"))
                profiles |= NET_FW_PROFILE2_PUBLIC;
            else
            {
                free(profiles_text);
                return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
            }
            if (!part) break;
            start = part + 1;
        } while (*start);
        free(profiles_text);
        if (!profiles)
            return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }
    hr = INetFwRule_put_Profiles(Rule, profiles);
    if (FAILED(hr)) return hr;

    if (Arguments->Enabled)
    {
        if (!_wcsicmp(Arguments->Enabled, L"yes") || !_wcsicmp(Arguments->Enabled, L"true"))
            enabled = VARIANT_TRUE;
        else if (!_wcsicmp(Arguments->Enabled, L"no") || !_wcsicmp(Arguments->Enabled, L"false"))
            enabled = VARIANT_FALSE;
        else
            return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }
    hr = INetFwRule_put_Enabled(Rule, enabled);
    if (FAILED(hr)) return hr;

    hr = FirewallSetString(Rule, Rule->lpVtbl->put_Name, Arguments->Name);
    if (SUCCEEDED(hr) && Arguments->LocalPort)
        hr = FirewallSetString(Rule, Rule->lpVtbl->put_LocalPorts,
                               !_wcsicmp(Arguments->LocalPort, L"any") ? L"*" : Arguments->LocalPort);
    if (SUCCEEDED(hr) && Arguments->RemotePort)
        hr = FirewallSetString(Rule, Rule->lpVtbl->put_RemotePorts,
                               !_wcsicmp(Arguments->RemotePort, L"any") ? L"*" : Arguments->RemotePort);
    if (SUCCEEDED(hr) && Arguments->LocalAddress)
        hr = FirewallSetString(Rule, Rule->lpVtbl->put_LocalAddresses,
                               !_wcsicmp(Arguments->LocalAddress, L"any") ? L"*" : Arguments->LocalAddress);
    if (SUCCEEDED(hr) && Arguments->RemoteAddress)
        hr = FirewallSetString(Rule, Rule->lpVtbl->put_RemoteAddresses,
                               !_wcsicmp(Arguments->RemoteAddress, L"any") ? L"*" : Arguments->RemoteAddress);
    if (SUCCEEDED(hr) && Arguments->Program)
        hr = FirewallSetString(Rule, Rule->lpVtbl->put_ApplicationName, Arguments->Program);
    if (SUCCEEDED(hr) && Arguments->Description)
        hr = FirewallSetString(Rule, Rule->lpVtbl->put_Description, Arguments->Description);
    return hr;
}

DWORD
WINAPI
AdvFirewallAddRuleCommand(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    FIREWALL_RULE_ARGUMENTS arguments;
    INetFwPolicy2 *policy = NULL;
    INetFwRules *rules = NULL;
    INetFwRule *rule = NULL;
    HRESULT hr;
    DWORD error;

    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pvData);
    UNREFERENCED_PARAMETER(pbDone);
    if (pwszMachine) return ERROR_NOT_SUPPORTED;
    error = FirewallParseArguments(&arguments, argv, dwCurrentIndex, dwArgCount, FALSE);
    if (error != ERROR_SUCCESS) return error;
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return FirewallHresultToError(hr);
    hr = CoCreateInstance(&CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwRule, (void **)&rule);
    if (SUCCEEDED(hr))
        hr = FirewallSetRule(rule, &arguments);
    if (SUCCEEDED(hr))
        hr = FirewallGetRules(&policy, &rules);
    if (SUCCEEDED(hr))
        hr = INetFwRules_Add(rules, rule);
    error = FirewallHresultToError(hr);
    if (rules) INetFwRules_Release(rules);
    if (policy) INetFwPolicy2_Release(policy);
    if (rule) INetFwRule_Release(rule);
    CoUninitialize();
    return error;
}

DWORD
WINAPI
AdvFirewallDeleteRuleCommand(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    FIREWALL_RULE_ARGUMENTS arguments;
    INetFwPolicy2 *policy = NULL;
    INetFwRules *rules = NULL;
    BSTR name = NULL;
    HRESULT hr;
    DWORD error;

    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pvData);
    UNREFERENCED_PARAMETER(pbDone);
    if (pwszMachine) return ERROR_NOT_SUPPORTED;
    error = FirewallParseArguments(&arguments, argv, dwCurrentIndex, dwArgCount, TRUE);
    if (error != ERROR_SUCCESS) return error;
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return FirewallHresultToError(hr);
    hr = FirewallGetRules(&policy, &rules);
    if (SUCCEEDED(hr))
    {
        name = SysAllocString(arguments.Name);
        hr = name ? INetFwRules_Remove(rules, name) : E_OUTOFMEMORY;
    }
    error = FirewallHresultToError(hr);
    SysFreeString(name);
    if (rules) INetFwRules_Release(rules);
    if (policy) INetFwPolicy2_Release(policy);
    CoUninitialize();
    return error;
}

static DWORD
FirewallPrintRule(INetFwRule *rule)
{
    BSTR name = NULL;
    NET_FW_RULE_DIRECTION direction;
    NET_FW_ACTION action;
    LONG protocol;
    VARIANT_BOOL enabled;
    HRESULT hr;

    hr = INetFwRule_get_Name(rule, &name);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Direction(rule, &direction);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Action(rule, &action);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Protocol(rule, &protocol);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Enabled(rule, &enabled);
    if (SUCCEEDED(hr))
        ConPrintf(StdOut, L"%s: %s, %s, protocol %ld, %s\n", name,
                  direction == NET_FW_RULE_DIR_IN ? L"inbound" : L"outbound",
                  action == NET_FW_ACTION_ALLOW ? L"allow" : L"block", protocol,
                  enabled == VARIANT_TRUE ? L"enabled" : L"disabled");
    SysFreeString(name);
    return FirewallHresultToError(hr);
}

DWORD
WINAPI
AdvFirewallShowRuleCommand(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    FIREWALL_RULE_ARGUMENTS arguments;
    INetFwPolicy2 *policy = NULL;
    INetFwRules *rules = NULL;
    HRESULT hr;
    DWORD error;
    BOOL initialized = FALSE;

    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pvData);
    UNREFERENCED_PARAMETER(pbDone);
    if (pwszMachine) return ERROR_NOT_SUPPORTED;
    error = FirewallParseArguments(&arguments, argv, dwCurrentIndex, dwArgCount, TRUE);
    if (error != ERROR_SUCCESS) return error;
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return FirewallHresultToError(hr);
    initialized = TRUE;
    hr = FirewallGetRules(&policy, &rules);
    if (SUCCEEDED(hr) && arguments.Name && _wcsicmp(arguments.Name, L"all"))
    {
        INetFwRule *rule;
        BSTR name = SysAllocString(arguments.Name);

        if (!name)
            hr = E_OUTOFMEMORY;
        else
            hr = INetFwRules_Item(rules, name, &rule);
        SysFreeString(name);
        if (SUCCEEDED(hr))
        {
            error = FirewallPrintRule(rule);
            INetFwRule_Release(rule);
            hr = error ? HRESULT_FROM_WIN32(error) : S_OK;
        }
    }
    else if (SUCCEEDED(hr))
    {
        IUnknown *enumerator = NULL;
        IEnumVARIANT *enumvar = NULL;

        hr = INetFwRules_get__NewEnum(rules, &enumerator);
        if (SUCCEEDED(hr))
            hr = IUnknown_QueryInterface(enumerator, &IID_IEnumVARIANT, (void **)&enumvar);
        if (enumerator) IUnknown_Release(enumerator);
        while (SUCCEEDED(hr) && enumvar)
        {
            VARIANT value;
            ULONG fetched = 0;

            VariantInit(&value);
            hr = IEnumVARIANT_Next(enumvar, 1, &value, &fetched);
            if (hr == S_FALSE)
                break;
            if (SUCCEEDED(hr) && fetched == 1 && V_VT(&value) == VT_DISPATCH)
            {
                INetFwRule *rule;

                hr = IDispatch_QueryInterface(V_DISPATCH(&value), &IID_INetFwRule,
                                              (void **)&rule);
                if (SUCCEEDED(hr))
                {
                    error = FirewallPrintRule(rule);
                    INetFwRule_Release(rule);
                    if (error) hr = HRESULT_FROM_WIN32(error);
                }
            }
            else if (SUCCEEDED(hr))
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            VariantClear(&value);
        }
        if (enumvar) IEnumVARIANT_Release(enumvar);
    }
    error = FirewallHresultToError(hr);
    if (rules) INetFwRules_Release(rules);
    if (policy) INetFwPolicy2_Release(policy);
    if (initialized) CoUninitialize();
    return error;
}

DWORD
CDECL
PrintError(
    _In_opt_ HANDLE hModule,
    _In_ DWORD dwErrId,
    ...)
{
    INT Length;
    va_list ap;

    va_start(ap, dwErrId);

    if (hModule)
    {
        Length = ConResMsgPrintfExV(StdErr, hModule, 0, dwErrId,
                                    LANG_USER_DEFAULT, &ap);
    }
    else
    {
        if ((dwErrId > NETSH_ERROR_BASE) && (dwErrId < NETSH_ERROR_END))
        {
            Length = ConResMsgPrintfExV(StdErr, g_hModule, 0, dwErrId,
                                        LANG_USER_DEFAULT, &ap);
        }
        else
        {
            Length = ConMsgPrintfV(StdErr, FORMAT_MESSAGE_FROM_SYSTEM,
                                   NULL, dwErrId,
                                   LANG_USER_DEFAULT, &ap);
        }
    }

    va_end(ap);

    return (DWORD)Length;
}

DWORD
CDECL
PrintMessageFromModule(
    _In_ HANDLE hModule,
    _In_ DWORD  dwMsgId,
    ...)
{
    INT Length;
    va_list ap;

    va_start(ap, dwMsgId);
    Length = ConResMsgPrintfExV(StdOut, hModule, 0, dwMsgId,
                                LANG_USER_DEFAULT, &ap);
    va_end(ap);

    return (DWORD)Length;
}

DWORD
CDECL
PrintMessage(
    _In_ LPCWSTR pwszFormat,
    ...)
{
    INT Length;
    va_list ap;

    va_start(ap, pwszFormat);
    Length = ConPrintfV(StdOut, pwszFormat, ap);
    va_end(ap);

    return (DWORD)Length;
}
