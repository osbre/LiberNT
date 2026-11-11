/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests that every kind of wait takes exactly one semaphore count
 * COPYRIGHT:   Copyright 2026 Ostap Brehin <osbre@protonmail.com>
 */

#include "precomp.h"

#define WAITER_COUNT 4
#define POSTER_COUNT 4

typedef enum
{
    WaitSingle,
    WaitSingleTimed,
    WaitAnySecond,
    WaitAllPair,
    WaitAlertable,
    WaitSignalAndWait,
} WAIT_KIND;

typedef struct
{
    WAIT_KIND Kind;
    HANDLE Semaphore;
    HANDLE Other;
    DWORD Result;
} WAITER;

static LONG QueryCount(HANDLE Semaphore, LONG *Maximum)
{
    SEMAPHORE_BASIC_INFORMATION Info = { -1, -1 };
    NTSTATUS Status;

    Status = NtQuerySemaphore(Semaphore, SemaphoreBasicInformation, &Info, sizeof(Info), NULL);
    ok(Status == STATUS_SUCCESS, "NtQuerySemaphore 0x%lx\n", Status);
    if (Maximum)
        *Maximum = Info.MaximumCount;
    return Info.CurrentCount;
}

static DWORD WINAPI WaiterThread(PVOID Parameter)
{
    WAITER *Waiter = Parameter;
    HANDLE Handles[2];

    switch (Waiter->Kind)
    {
        case WaitSingle:
            Waiter->Result = WaitForSingleObject(Waiter->Semaphore, INFINITE);
            break;
        case WaitSingleTimed:
            Waiter->Result = WaitForSingleObject(Waiter->Semaphore, 10000);
            break;
        case WaitAnySecond:
            Handles[0] = Waiter->Other;
            Handles[1] = Waiter->Semaphore;
            Waiter->Result = WaitForMultipleObjects(2, Handles, FALSE, INFINITE);
            break;
        case WaitAllPair:
            Handles[0] = Waiter->Semaphore;
            Handles[1] = Waiter->Other;
            Waiter->Result = WaitForMultipleObjects(2, Handles, TRUE, INFINITE);
            break;
        case WaitAlertable:
            do
                Waiter->Result = WaitForSingleObjectEx(Waiter->Semaphore, INFINITE, TRUE);
            while (Waiter->Result == WAIT_IO_COMPLETION);
            break;
        case WaitSignalAndWait:
            Waiter->Result = SignalObjectAndWait(Waiter->Other, Waiter->Semaphore, INFINITE, FALSE);
            break;
    }
    return 0;
}

static BOOL IsWaiting(HANDLE Thread)
{
    return WaitForSingleObject(Thread, 100) == WAIT_TIMEOUT;
}

static VOID CALLBACK EmptyApc(ULONG_PTR Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
}

static void TestLimit(void)
{
    HANDLE Semaphore;
    LONG Previous, Maximum;
    NTSTATUS Status;
    BOOL Ret;

    Semaphore = CreateSemaphoreW(NULL, 0, 1, NULL);
    ok(Semaphore != NULL, "CreateSemaphoreW %lu\n", GetLastError());
    if (!Semaphore)
        return;

    Previous = 77;
    Ret = ReleaseSemaphore(Semaphore, 1, &Previous);
    ok(Ret && Previous == 0, "first release %d, previous %ld\n", Ret, Previous);

    Previous = 77;
    SetLastError(0xdeadbeef);
    Ret = ReleaseSemaphore(Semaphore, 1, &Previous);
    ok(!Ret, "release past the limit succeeded\n");
    ok(GetLastError() == ERROR_TOO_MANY_POSTS, "error %lu\n", GetLastError());
    ok(Previous == 77, "previous %ld\n", Previous);

    Previous = 77;
    Status = NtReleaseSemaphore(Semaphore, 1, &Previous);
    ok(Status == STATUS_SEMAPHORE_LIMIT_EXCEEDED, "NtReleaseSemaphore 0x%lx\n", Status);
    ok(Previous == 77, "previous %ld\n", Previous);
    ok(QueryCount(Semaphore, &Maximum) == 1 && Maximum == 1, "count after the refused releases\n");

    ok(WaitForSingleObject(Semaphore, 0) == WAIT_OBJECT_0, "wait on a signaled semaphore\n");
    ok(QueryCount(Semaphore, NULL) == 0, "the wait did not take the count\n");
    ok(WaitForSingleObject(Semaphore, 0) == WAIT_TIMEOUT, "wait on an empty semaphore\n");

    Status = NtReleaseSemaphore(Semaphore, 2, &Previous);
    ok(Status == STATUS_SEMAPHORE_LIMIT_EXCEEDED, "release of 2 past a limit of 1: 0x%lx\n", Status);
    ok(QueryCount(Semaphore, NULL) == 0, "a refused release changed the count\n");
    CloseHandle(Semaphore);
}

static void TestBlockedWaiter(WAIT_KIND Kind, const char *Name)
{
    WAITER Waiter = { Kind, NULL, NULL, 0xdead };
    HANDLE Thread;
    LONG Previous;
    BOOL Ret;

    Waiter.Semaphore = CreateSemaphoreW(NULL, 0, 1, NULL);
    if (Kind == WaitAnySecond || Kind == WaitAllPair || Kind == WaitSignalAndWait)
        Waiter.Other = CreateEventW(NULL, TRUE, FALSE, NULL);

    Thread = CreateThread(NULL, 0, WaiterThread, &Waiter, 0, NULL);
    ok(Thread != NULL, "%s: CreateThread %lu\n", Name, GetLastError());
    if (!Thread)
        goto Cleanup;
    ok(IsWaiting(Thread), "%s: the waiter did not block\n", Name);

    if (Kind == WaitAlertable)
    {
        ok(QueueUserAPC(EmptyApc, Thread, 0), "%s: QueueUserAPC %lu\n", Name, GetLastError());
        ok(IsWaiting(Thread), "%s: the waiter left after the APC\n", Name);
        ok(QueryCount(Waiter.Semaphore, NULL) == 0, "%s: the APC changed the count\n", Name);
    }

    Ret = ReleaseSemaphore(Waiter.Semaphore, 1, &Previous);
    ok(Ret && Previous == 0, "%s: release %d, previous %ld\n", Name, Ret, Previous);

    if (Kind == WaitAllPair)
    {
        ok(IsWaiting(Thread), "%s: wait-all returned with one object signaled\n", Name);
        ok(QueryCount(Waiter.Semaphore, NULL) == 1, "%s: wait-all took the count early\n", Name);
        SetEvent(Waiter.Other);
    }

    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "%s: the waiter did not wake\n", Name);
    ok(Waiter.Result == (Kind == WaitAnySecond ? WAIT_OBJECT_0 + 1 : WAIT_OBJECT_0),
       "%s: wait result %lu\n", Name, Waiter.Result);
    ok(QueryCount(Waiter.Semaphore, NULL) == 0, "%s: the waiter did not take the count\n", Name);

    Ret = ReleaseSemaphore(Waiter.Semaphore, 1, &Previous);
    ok(Ret && Previous == 0, "%s: release after the wake %d, previous %ld\n", Name, Ret, Previous);
    CloseHandle(Thread);

Cleanup:
    CloseHandle(Waiter.Semaphore);
    if (Waiter.Other)
        CloseHandle(Waiter.Other);
}

static void TestWaitAnyOrder(void)
{
    HANDLE Semaphore, Event, Handles[2];
    DWORD Result;

    Semaphore = CreateSemaphoreW(NULL, 1, 1, NULL);
    Event = CreateEventW(NULL, FALSE, TRUE, NULL);

    Handles[0] = Event;
    Handles[1] = Semaphore;
    Result = WaitForMultipleObjects(2, Handles, FALSE, 0);
    ok(Result == WAIT_OBJECT_0, "event first: result %lu\n", Result);
    ok(QueryCount(Semaphore, NULL) == 1, "event first: the semaphore lost its count\n");
    ok(WaitForSingleObject(Event, 0) == WAIT_TIMEOUT, "event first: the event stayed signaled\n");

    SetEvent(Event);
    Handles[0] = Semaphore;
    Handles[1] = Event;
    Result = WaitForMultipleObjects(2, Handles, FALSE, 0);
    ok(Result == WAIT_OBJECT_0, "semaphore first: result %lu\n", Result);
    ok(QueryCount(Semaphore, NULL) == 0, "semaphore first: the count was not taken\n");
    ok(WaitForSingleObject(Event, 0) == WAIT_OBJECT_0, "semaphore first: the event was reset\n");

    CloseHandle(Event);
    CloseHandle(Semaphore);
}

static void TestPartialRelease(void)
{
    WAITER Waiters[WAITER_COUNT];
    HANDLE Threads[WAITER_COUNT], Pending[WAITER_COUNT], Semaphore;
    DWORD Woken, Left, Result, i;
    LONG Previous;

    Semaphore = CreateSemaphoreW(NULL, 0, WAITER_COUNT, NULL);
    for (i = 0; i < WAITER_COUNT; ++i)
    {
        Waiters[i].Kind = WaitSingle;
        Waiters[i].Semaphore = Semaphore;
        Waiters[i].Other = NULL;
        Waiters[i].Result = 0xdead;
        Threads[i] = CreateThread(NULL, 0, WaiterThread, &Waiters[i], 0, NULL);
        ok(Threads[i] != NULL, "CreateThread %lu\n", GetLastError());
        if (!Threads[i])
            return;
        Pending[i] = Threads[i];
    }
    Sleep(100);

    ok(ReleaseSemaphore(Semaphore, 2, &Previous) && Previous == 0, "release of 2, previous %ld\n", Previous);
    Left = WAITER_COUNT;
    for (Woken = 0; Woken < 2; ++Woken)
    {
        Result = WaitForMultipleObjects(Left, Pending, FALSE, 5000);
        if (Result >= WAIT_OBJECT_0 + Left)
            break;
        Pending[Result - WAIT_OBJECT_0] = Pending[--Left];
    }
    ok(Woken == 2, "a release of 2 woke %lu waiters in 5 s\n", Woken);
    ok(WaitForMultipleObjects(Left, Pending, FALSE, 200) == WAIT_TIMEOUT, "a release of 2 woke more than 2 waiters\n");
    ok(QueryCount(Semaphore, NULL) == 0, "count %ld after waking 2 waiters\n", QueryCount(Semaphore, NULL));

    ok(ReleaseSemaphore(Semaphore, 2, &Previous) && Previous == 0, "second release of 2, previous %ld\n", Previous);
    ok(WaitForMultipleObjects(WAITER_COUNT, Threads, TRUE, 5000) == WAIT_OBJECT_0, "the other waiters did not wake\n");
    ok(QueryCount(Semaphore, NULL) == 0, "count %ld after waking every waiter\n", QueryCount(Semaphore, NULL));
    for (i = 0; i < WAITER_COUNT; ++i)
    {
        ok(Waiters[i].Result == WAIT_OBJECT_0, "waiter %lu result %lu\n", i, Waiters[i].Result);
        CloseHandle(Threads[i]);
    }
    CloseHandle(Semaphore);
}

typedef struct
{
    HANDLE Semaphore;
    volatile LONG *Stop;
    LONG Posted;
    LONG Refused;
} POSTER;

static DWORD WINAPI PosterThread(PVOID Parameter)
{
    POSTER *Poster = Parameter;

    while (!*Poster->Stop)
    {
        if (NtReleaseSemaphore(Poster->Semaphore, 1, NULL) == STATUS_SEMAPHORE_LIMIT_EXCEEDED)
            ++Poster->Refused;
        else
            ++Poster->Posted;
        SwitchToThread();
    }
    return 0;
}

static void TestPostersAndConsumer(void)
{
    POSTER Posters[POSTER_COUNT];
    HANDLE Threads[POSTER_COUNT], Semaphore;
    volatile LONG Stop = 0;
    LONG Posted = 0, Refused = 0, Consumed = 0;
    ULONGLONG Deadline;
    DWORD i;

    Semaphore = CreateSemaphoreW(NULL, 0, 1, NULL);
    for (i = 0; i < POSTER_COUNT; ++i)
    {
        Posters[i].Semaphore = Semaphore;
        Posters[i].Stop = &Stop;
        Posters[i].Posted = 0;
        Posters[i].Refused = 0;
        Threads[i] = CreateThread(NULL, 0, PosterThread, &Posters[i], 0, NULL);
        ok(Threads[i] != NULL, "CreateThread %lu\n", GetLastError());
        if (!Threads[i])
            return;
    }

    Deadline = GetTickCount64() + 1000;
    while (GetTickCount64() < Deadline)
    {
        if (WaitForSingleObject(Semaphore, 100) == WAIT_OBJECT_0)
            ++Consumed;
    }
    InterlockedExchange((LONG *)&Stop, 1);
    WaitForMultipleObjects(POSTER_COUNT, Threads, TRUE, INFINITE);
    for (i = 0; i < POSTER_COUNT; ++i)
    {
        Posted += Posters[i].Posted;
        Refused += Posters[i].Refused;
        CloseHandle(Threads[i]);
    }

    trace("%ld posted, %ld refused, %ld consumed\n", Posted, Refused, Consumed);
    ok(Consumed > 0, "the consumer never woke\n");
    ok(Posted == Consumed + QueryCount(Semaphore, NULL),
       "%ld posted but %ld consumed and %ld left\n", Posted, Consumed, QueryCount(Semaphore, NULL));
    CloseHandle(Semaphore);
}

START_TEST(SemaphoreWait)
{
    TestLimit();
    TestBlockedWaiter(WaitSingle, "single");
    TestBlockedWaiter(WaitSingleTimed, "single timed");
    TestBlockedWaiter(WaitAnySecond, "wait any");
    TestBlockedWaiter(WaitAllPair, "wait all");
    TestBlockedWaiter(WaitAlertable, "alertable");
    TestBlockedWaiter(WaitSignalAndWait, "signal and wait");
    TestWaitAnyOrder();
    TestPartialRelease();
    TestPostersAndConsumer();
}
