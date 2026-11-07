/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that the boot loader passes the BCD debug port ahead of the load options
 * COPYRIGHT:   Copyright 2026 Ostap Brehin <osbre@protonmail.com>
 */

#include <kmt_test.h>
#include <ndk/cmfuncs.h>

START_TEST(KdStartOptions)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"SystemStartOptions");
    OBJECT_ATTRIBUTES ObjectAttributes;
    PKEY_VALUE_PARTIAL_INFORMATION Partial;
    UCHAR Buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 4096 * sizeof(WCHAR)];
    PWCHAR Options, Token, Context;
    PWCHAR Port = NULL;
    ULONG ResultLength;
    BOOLEAN Debug = FALSE;
    HANDLE KeyHandle;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Partial = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    Status = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, Partial,
                             sizeof(Buffer) - sizeof(WCHAR), &ResultLength);
    NtClose(KeyHandle);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    ok_eq_ulong(Partial->Type, (ULONG)REG_SZ);
    Options = (PWCHAR)Partial->Data;
    _wcsupr(Options);
    trace("SystemStartOptions: %ls\n", Options);

    for (Token = wcstok_s(Options, L" ", &Context); Token != NULL; Token = wcstok_s(NULL, L" ", &Context))
    {
        if (wcscmp(Token, L"DEBUG") == 0)
        {
            Debug = TRUE;
            Port = wcstok_s(NULL, L" ", &Context);
            break;
        }
    }

    if (skip(Debug, "The kernel debugger is not enabled\n"))
        return;

    ok(Port != NULL && wcsncmp(Port, L"DEBUGPORT=", 10) == 0,
       "DEBUG is followed by %ls instead of the BCD debug port\n", Port ? Port : L"nothing");
}
