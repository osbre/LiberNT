/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for GetCurrentPackageId
 * COPYRIGHT:   Copyright 2026 Ostap Brehin <osbre@protonmail.com>
 */

#include "precomp.h"

typedef LONG (WINAPI *PGET_CURRENT_PACKAGE_ID)(UINT32 *, BYTE *);

static VOID
CheckFunction(
    _In_ PGET_CURRENT_PACKAGE_ID Function,
    _In_ PCSTR Provider)
{
    BYTE Buffer[64];
    UINT32 Length;
    DWORD Error;
    LONG Result;

    Length = 0;
    SetLastError(0x33333333);
    Result = Function(&Length, NULL);
    Error = GetLastError();
    ok_long(Result, APPMODEL_ERROR_NO_PACKAGE);
    ok_long(Length, 0);
    ok_long(Error, 0x33333333);

    memset(Buffer, 0xA5, sizeof(Buffer));
    Length = sizeof(Buffer);
    SetLastError(0x33333333);
    Result = Function(&Length, Buffer);
    Error = GetLastError();
    ok_long(Result, APPMODEL_ERROR_NO_PACKAGE);
    ok_long(Length, sizeof(Buffer));
    ok_int(Buffer[0], 0xA5);
    ok_int(Buffer[sizeof(Buffer) - 1], 0xA5);
    ok_long(Error, 0x33333333);

    Length = 0;
    SetLastError(0x33333333);
    Result = Function(&Length, Buffer);
    Error = GetLastError();
    ok_long(Result, APPMODEL_ERROR_NO_PACKAGE);
    ok_long(Length, 0);
    ok_long(Error, 0x33333333);

    Length = sizeof(Buffer);
    SetLastError(0x33333333);
    Result = Function(&Length, NULL);
    Error = GetLastError();
    ok_long(Result, ERROR_INVALID_PARAMETER);
    ok_long(Length, sizeof(Buffer));
    ok_long(Error, 0x33333333);

    SetLastError(0x33333333);
    Result = Function(NULL, NULL);
    Error = GetLastError();
    ok_long(Result, ERROR_INVALID_PARAMETER);
    ok_long(Error, 0x33333333);

    SetLastError(0x33333333);
    Result = Function(NULL, Buffer);
    Error = GetLastError();
    ok_long(Result, ERROR_INVALID_PARAMETER);
    ok_long(Error, 0x33333333);

    trace("%s current-package-id query contract complete\n", Provider);
}

START_TEST(GetCurrentPackageId)
{
    PGET_CURRENT_PACKAGE_ID Kernel32Function;
    PGET_CURRENT_PACKAGE_ID KernelBaseFunction;
    DWORD Error;
    HMODULE Kernel32;
    HMODULE KernelBase;

    Kernel32 = GetModuleHandleW(L"kernel32.dll");
    Kernel32Function = (PGET_CURRENT_PACKAGE_ID)(PVOID)GetProcAddress(Kernel32, "GetCurrentPackageId");
    ok(Kernel32Function != NULL, "GetCurrentPackageId is not exported by kernel32\n");
    if (Kernel32Function)
        CheckFunction(Kernel32Function, "kernel32");

    KernelBase = LoadLibraryW(L"kernelbase.dll");
    Error = GetLastError();
    ok(KernelBase != NULL, "Failed to load kernelbase.dll: %lu\n", Error);
    KernelBaseFunction = NULL;
    if (KernelBase)
        KernelBaseFunction = (PGET_CURRENT_PACKAGE_ID)(PVOID)GetProcAddress(KernelBase, "GetCurrentPackageId");
    ok(KernelBaseFunction != NULL, "GetCurrentPackageId is not exported by kernelbase\n");
    if (KernelBaseFunction)
        CheckFunction(KernelBaseFunction, "kernelbase");

    if (KernelBase)
        FreeLibrary(KernelBase);
}
