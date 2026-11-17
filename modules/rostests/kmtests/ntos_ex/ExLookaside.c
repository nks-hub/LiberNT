/*
 * PROJECT:         LiberNT kernel-mode tests
 * LICENSE:         GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:         Kernel-Mode Test Suite lookaside list API
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

#define TAG_TEST 'sLmK'

static
VOID
TestNPagedLookaside(VOID)
{
    NPAGED_LOOKASIDE_LIST List;
    PVOID Blocks[8];
    ULONG i;

    ExInitializeNPagedLookasideList(&List, NULL, NULL, 0, 64, TAG_TEST, 0);

    for (i = 0; i < 8; i++)
    {
        Blocks[i] = ExAllocateFromNPagedLookasideList(&List);
        ok(Blocks[i] != NULL, "npaged alloc %lu failed\n", i);
        if (Blocks[i]) RtlFillMemory(Blocks[i], 64, 0x5A);
    }
    for (i = 0; i < 8; i++)
        if (Blocks[i]) ExFreeToNPagedLookasideList(&List, Blocks[i]);

    Blocks[0] = ExAllocateFromNPagedLookasideList(&List);
    ok(Blocks[0] != NULL, "npaged realloc failed\n");
    if (Blocks[0]) ExFreeToNPagedLookasideList(&List, Blocks[0]);

    ExDeleteNPagedLookasideList(&List);
}

static
VOID
TestPagedLookaside(VOID)
{
    PAGED_LOOKASIDE_LIST List;
    PVOID Block;

    ExInitializePagedLookasideList(&List, NULL, NULL, 0, 128, TAG_TEST, 0);

    Block = ExAllocateFromPagedLookasideList(&List);
    ok(Block != NULL, "paged alloc failed\n");
    if (Block)
    {
        RtlFillMemory(Block, 128, 0xA5);
        ExFreeToPagedLookasideList(&List, Block);
    }

    Block = ExAllocateFromPagedLookasideList(&List);
    ok(Block != NULL, "paged realloc failed\n");
    if (Block) ExFreeToPagedLookasideList(&List, Block);

    ExDeletePagedLookasideList(&List);
}

static volatile LONG CustomAllocs;
static volatile LONG CustomFrees;

static
PVOID
NTAPI
CustomAllocate(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag)
{
    InterlockedIncrement(&CustomAllocs);
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
}

static
VOID
NTAPI
CustomFree(
    _In_ PVOID Buffer)
{
    InterlockedIncrement(&CustomFrees);
    ExFreePoolWithTag(Buffer, TAG_TEST);
}

static
VOID
TestCustomRoutines(VOID)
{
    NPAGED_LOOKASIDE_LIST List;
    PVOID Block;

    CustomAllocs = 0;
    CustomFrees = 0;

    ExInitializeNPagedLookasideList(&List, CustomAllocate, CustomFree, 0, 32, TAG_TEST, 0);

    Block = ExAllocateFromNPagedLookasideList(&List);
    ok(Block != NULL, "custom alloc failed\n");
    ok_eq_long(CustomAllocs, 1L);
    if (Block) ExFreeToNPagedLookasideList(&List, Block);
    ok_eq_long(CustomFrees, 0L);

    ExDeleteNPagedLookasideList(&List);
    ok_eq_long(CustomFrees, 1L);
}

static
VOID
TestLookasideEx(VOID)
{
    PLOOKASIDE_LIST_EX List;
    PVOID Block;
    NTSTATUS Status;

    List = ExAllocatePoolWithTag(NonPagedPool, sizeof(*List), TAG_TEST);
    ok(List != NULL, "no pool for LOOKASIDE_LIST_EX\n");
    if (List == NULL) return;

    Status = ExInitializeLookasideListEx(List, NULL, NULL, NonPagedPool, 0, 96, TAG_TEST, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Block = ExAllocateFromLookasideListEx(List);
        ok(Block != NULL, "ex alloc failed\n");
        ok_eq_ulong(List->L.TotalAllocates, 1UL);
        ok_eq_ulong(List->L.AllocateMisses, 1UL);
        if (Block) ExFreeToLookasideListEx(List, Block);
        ok_eq_ulong(List->L.TotalFrees, 1UL);
        Block = ExAllocateFromLookasideListEx(List);
        ok(Block != NULL, "ex realloc failed\n");
        if (Block) ExFreeToLookasideListEx(List, Block);
        ExFlushLookasideListEx(List);
        ok(ExQueryDepthSList(&List->L.ListHead) == 0, "flush left entries\n");
        ExDeleteLookasideListEx(List);
    }
    ExFreePoolWithTag(List, TAG_TEST);
}

static
VOID
TestLookasideExParameters(VOID)
{
    static const struct
    {
        POOL_TYPE PoolType;
        ULONG Flags;
        NTSTATUS Expected;
    } Tests[] =
    {
        { NonPagedPoolNx, 0, STATUS_SUCCESS },
        { NonPagedPool, EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL, STATUS_SUCCESS },
        { NonPagedPoolNx, EX_LOOKASIDE_LIST_EX_FLAGS_FAIL_NO_RAISE, STATUS_SUCCESS },
        { PagedPool, 0x4, STATUS_INVALID_PARAMETER_5 },
        { NonPagedPoolMustSucceed, 0, STATUS_INVALID_PARAMETER_4 },
    };
    PLOOKASIDE_LIST_EX List;
    PVOID Block;
    NTSTATUS Status;
    ULONG Index;

    List = ExAllocatePoolWithTag(NonPagedPool, sizeof(*List), TAG_TEST);
    ok(List != NULL, "no pool for LOOKASIDE_LIST_EX\n");
    if (List == NULL) return;

    for (Index = 0; Index < RTL_NUMBER_OF(Tests); Index++)
    {
        Status = ExInitializeLookasideListEx(List, NULL, NULL, Tests[Index].PoolType, Tests[Index].Flags, 96, TAG_TEST, 0);
        ok(Status == Tests[Index].Expected, "%lu: pool type %d, flags 0x%lx: status 0x%lx, expected 0x%lx\n",
           Index, Tests[Index].PoolType, Tests[Index].Flags, Status, Tests[Index].Expected);
        if (!NT_SUCCESS(Status)) continue;

        Block = ExAllocateFromLookasideListEx(List);
        ok(Block != NULL, "%lu: allocation failed\n", Index);
        if (Block) ExFreeToLookasideListEx(List, Block);
        ExDeleteLookasideListEx(List);
    }
    ExFreePoolWithTag(List, TAG_TEST);
}

START_TEST(ExLookaside)
{
    TestNPagedLookaside();
    TestPagedLookaside();
    TestCustomRoutines();
    TestLookasideEx();
    TestLookasideExParameters();
}
