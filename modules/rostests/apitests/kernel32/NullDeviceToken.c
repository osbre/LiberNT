/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Opening the null device under restricted and low integrity tokens
 * COPYRIGHT:   Copyright 2026 Ostap Brehin <osbre@protonmail.com>
 */

#include "precomp.h"

static HANDLE MakeToken(BOOL Restrict, BOOL SetIntegrity, DWORD IntegrityRid)
{
    SID_IDENTIFIER_AUTHORITY world = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY nt = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY label = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    SID_AND_ATTRIBUTES restricting[3] = {0};
    TOKEN_MANDATORY_LABEL integrity = {{0}};
    HANDLE process, restricted = NULL, impersonation = NULL;
    DWORD i;
    PSID il = NULL;
    BOOL ret;

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &process);
    ok(ret, "OpenProcessToken failed: %lu\n", GetLastError());
    if (!ret)
        return NULL;

    AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &restricting[0].Sid);
    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0,
                             &restricting[1].Sid);
    AllocateAndInitializeSid(&nt, 1, SECURITY_RESTRICTED_CODE_RID, 0, 0, 0, 0, 0, 0, 0, &restricting[2].Sid);

    ret = CreateRestrictedToken(process, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL,
                                Restrict ? ARRAYSIZE(restricting) : 0, Restrict ? restricting : NULL, &restricted);
    ok(ret, "CreateRestrictedToken failed: %lu\n", GetLastError());

    if (ret)
    {
        ret = DuplicateTokenEx(restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation,
                               &impersonation);
        ok(ret, "DuplicateTokenEx failed: %lu\n", GetLastError());
    }

    if (impersonation && SetIntegrity)
    {
        AllocateAndInitializeSid(&label, 1, IntegrityRid, 0, 0, 0, 0, 0, 0, 0, &il);
        integrity.Label.Sid = il;
        integrity.Label.Attributes = SE_GROUP_INTEGRITY;
        ret = SetTokenInformation(impersonation, TokenIntegrityLevel, &integrity,
                                  sizeof(integrity) + GetLengthSid(il));
        ok(ret, "TokenIntegrityLevel failed: %lu\n", GetLastError());
        FreeSid(il);
    }

    for (i = 0; i < ARRAYSIZE(restricting); i++)
        FreeSid(restricting[i].Sid);
    if (restricted)
        CloseHandle(restricted);
    CloseHandle(process);
    return impersonation;
}

static DWORD OpenUnder(HANDLE Token, PCWSTR Name, DWORD Access)
{
    HANDLE file;
    DWORD error = ERROR_SUCCESS;

    if (!SetThreadToken(NULL, Token))
        return GetLastError() | 0x80000000;
    file = CreateFileW(Name, Access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        error = GetLastError();
    else
        CloseHandle(file);
    SetThreadToken(NULL, NULL);
    return error;
}

static void CheckLowLabel(PCWSTR Name)
{
    SYSTEM_MANDATORY_LABEL_ACE *ace;
    PSECURITY_DESCRIPTOR sd;
    BOOL present, defaulted;
    DWORD size = 0;
    HANDLE file;
    PACL sacl;

    file = CreateFileW(Name, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "Opening %s for READ_CONTROL failed: %lu\n", wine_dbgstr_w(Name), GetLastError());
    if (file == INVALID_HANDLE_VALUE)
        return;

    GetKernelObjectSecurity(file, LABEL_SECURITY_INFORMATION, NULL, 0, &size);
    ok(size != 0, "%s label size query failed: %lu\n", wine_dbgstr_w(Name), GetLastError());
    if (size == 0)
    {
        CloseHandle(file);
        return;
    }
    sd = HeapAlloc(GetProcessHeap(), 0, size);
    if (!GetKernelObjectSecurity(file, LABEL_SECURITY_INFORMATION, sd, size, &size))
    {
        ok(0, "%s label query failed: %lu\n", wine_dbgstr_w(Name), GetLastError());
        HeapFree(GetProcessHeap(), 0, sd);
        CloseHandle(file);
        return;
    }
    present = FALSE;
    sacl = NULL;
    ok(GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted), "GetSecurityDescriptorSacl failed\n");
    ok(present && sacl, "%s has no label\n", wine_dbgstr_w(Name));
    if (present && sacl)
    {
        ok(sacl->AceCount == 1, "%s label ACE count %u\n", wine_dbgstr_w(Name), sacl->AceCount);
        if (sacl->AceCount >= 1 && GetAce(sacl, 0, (void **)&ace))
        {
            SID_IDENTIFIER_AUTHORITY label = {SECURITY_MANDATORY_LABEL_AUTHORITY};
            PSID sid = (PSID)&ace->SidStart;

            ok(ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE, "ACE type %u\n", ace->Header.AceType);
            ok(ace->Header.AceFlags == 0, "ACE flags 0x%x\n", ace->Header.AceFlags);
            ok(ace->Mask == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "ACE mask 0x%lx\n", ace->Mask);
            ok(!memcmp(GetSidIdentifierAuthority(sid), &label, sizeof(label)) &&
               *GetSidSubAuthorityCount(sid) == 1 && *GetSidSubAuthority(sid, 0) == SECURITY_MANDATORY_LOW_RID,
               "%s label is not low\n", wine_dbgstr_w(Name));
        }
    }
    HeapFree(GetProcessHeap(), 0, sd);
    CloseHandle(file);
}

START_TEST(NullDeviceToken)
{
    static const struct
    {
        BOOL Restrict;
        BOOL SetIntegrity;
        DWORD Integrity;
        BOOL WriteDenied;
        const char *Name;
    } tokens[] =
    {
        {FALSE, FALSE, 0, FALSE, "plain"},
        {TRUE, FALSE, 0, FALSE, "restricted"},
        {FALSE, TRUE, SECURITY_MANDATORY_LOW_RID, FALSE, "low"},
        {FALSE, TRUE, SECURITY_MANDATORY_UNTRUSTED_RID, TRUE, "untrusted"},
        {TRUE, TRUE, SECURITY_MANDATORY_LOW_RID, FALSE, "restricted low"},
        {TRUE, TRUE, SECURITY_MANDATORY_UNTRUSTED_RID, TRUE, "restricted untrusted"},
    };
    static const DWORD accesses[] =
    {
        GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE, FILE_READ_ATTRIBUTES, MAXIMUM_ALLOWED,
    };
    static const PCWSTR names[] = {L"NUL", L"\\\\.\\NUL", L"\\\\?\\GLOBALROOT\\Device\\Null"};
    DWORD error, expected;
    HANDLE token;
    UINT t, a, n;

    CheckLowLabel(L"\\\\.\\NUL");
    CheckLowLabel(L"\\\\?\\GLOBALROOT\\Device\\Beep");
    CheckLowLabel(L"\\\\?\\GLOBALROOT\\Device\\KsecDD");

    for (t = 0; t < ARRAYSIZE(tokens); t++)
    {
        token = MakeToken(tokens[t].Restrict, tokens[t].SetIntegrity, tokens[t].Integrity);
        if (!token)
            continue;
        for (n = 0; n < ARRAYSIZE(names); n++)
        {
            for (a = 0; a < ARRAYSIZE(accesses); a++)
            {
                expected = (tokens[t].WriteDenied && (accesses[a] & GENERIC_WRITE)) ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
                error = OpenUnder(token, names[n], accesses[a]);
                ok(error == expected, "%s token, %s, access 0x%08lx: error %lu\n", tokens[t].Name,
                   wine_dbgstr_w(names[n]), accesses[a], error);
            }
        }
        CloseHandle(token);
    }
}
