#pragma once
#include <ntddk.h>

/*
*  Implemented according to the Intel SDM ver. September 2023
*/


typedef union _EPTP
{
	struct
	{
		UINT64 memoryType : 3; // 0 = Uncacheable (UC) ; 6 = Write - back(WB) ; others are reserved
		UINT64 eptPageWalkLen : 3; // value is 1 less than the actual walk length
		UINT64 dirtyAndAccessFlagEnable : 1;
		UINT64 supervisorShadowStackEnforce : 1; // enables enforcement of access rights for supervisor shadow-stack pages
		UINT64 reserved : 4;
		UINT64 pml4Addr : 36;
		UINT64 reserved2 : 16;
	} Bitfields;
	UINT64 flags;
} EPTP, *PEPTP;

// EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
typedef union _EPT_PML4E
{
	struct
	{
		UINT64 read : 1;
		UINT64 write : 1;
		UINT64 execute : 1;
		UINT64 reserved : 5;
		UINT64 accessedFlag : 1;
		UINT64 ignored : 1;
		UINT64 usermodeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 12;
	} Bitfields;
	UINT64 flags;
} EPT_PML4E, *PEPT_PML4E;

// EPT Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page
typedef union _EPT_PDPTE_HUGE_PAGE
{
	struct
	{
		UINT64 read : 1;
		UINT64 write : 1;
		UINT64 execute : 1;
		UINT64 memoryType : 3;
		UINT64 ignorePATMemoryType : 1;
		UINT64 reserved : 1; // Must be 1
		UINT64 accessedFlag : 1;
		UINT64 dirtyFlag : 1;
		UINT64 usermodeExecute : 1;
		UINT64 ignored : 1;
		UINT64 reserved2 : 18;
		UINT64 hugePagePhysicalAddr : 18;
		UINT64 reserved3 : 4;
		UINT64 ignored2 : 5;
		UINT64 verifyGuestPaging : 1;
		UINT64 pagingWriteAccess : 1;
		UINT64 ignored3 : 1;
		UINT64 supervisorShadowStack : 1;
		UINT64 ignored4 : 2;
		UINT64 suppressVE : 1; // Suppress #VE
	} Bitfields;
	UINT64 flags;
} EPT_PDPTE_HUGE_PAGE, *PEPT_PDPTE_HUGE_PAGE;

// EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Director
typedef union _EPT_PDPTE
{
	struct
	{
		UINT64 read : 1;
		UINT64 write : 1;
		UINT64 execute : 1;
		UINT64 reserved : 5;
		UINT64 accessedFlag : 1;
		UINT64 ignored : 1;
		UINT64 usermodeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 12;
	} Bitfields;
	UINT64 flags;
} EPT_PDPTE, *PEPT_PDPTE;

// EPT Page-Directory Entry (PDE) that Maps a 2-MByte Page
typedef union _EPT_PDE_LARGE_PAGE
{
	struct
	{
		UINT64 read : 1;
		UINT64 write : 1;
		UINT64 execute : 1;
		UINT64 memoryType : 3;
		UINT64 ignorePATMemoryType : 1;
		UINT64 reserved : 1; // Must be 1
		UINT64 accessedFlag : 1;
		UINT64 dirtyFlag : 1;
		UINT64 usermodeExecute : 1;
		UINT64 ignored : 1;
		UINT64 reserved2 : 9;
		UINT64 physicalAddress : 27;
		UINT64 reserved3 : 4;
		UINT64 ignored2 : 5;
		UINT64 verifyGuestPaging : 1;
		UINT64 pagingWriteAccess : 1;
		UINT64 ignored3 : 1;
		UINT64 supervisorShadowStack : 1;
		UINT64 ignored4 : 2;
		UINT64 suppressVE : 1; // Suppress #VE
	} Bitfields;
	UINT64 flags;
} EPT_PDE_LARGE_PAGE, *PEPT_PDE_LARGE_PAGE;

// EPT Page-Directory Entry (PDE) that References an EPT Page Table
typedef union _EPT_PDE
{
	struct
	{
		UINT64 read : 1;
		UINT64 write : 1;
		UINT64 execute : 1;
		UINT64 reserved : 5;
		UINT64 accessedFlag : 1;
		UINT64 ignored : 1;
		UINT64 usermodeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 12;
	} Bitfields;
	UINT64 flags;
} EPT_PDE, *PEPT_PDE;

// EPT Page-Table Entry that Maps a 4-KByte Page
typedef union _EPT_PTE
{
	struct
	{
		UINT64 read : 1;
		UINT64 write : 1;
		UINT64 execute : 1;
		UINT64 memoryType : 3;
		UINT64 ignorePATMemoryType : 1;
		UINT64 ignored : 1;
		UINT64 accessedFlag : 1;
		UINT64 dirtyFlag : 1;
		UINT64 usermodeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 5;
		UINT64 verifyGuestPaging : 1;
		UINT64 pagingWriteAccess : 1;
		UINT64 ignored4 : 1;
		UINT64 supervisorShadowStack : 1;
		UINT64 subPagePermissions : 1;
		UINT64 ignored5 : 1;
		UINT64 suppressVE : 1; // Suppress #VE
	} Bitfields;
	UINT64 flags;
} EPT_PTE, *PEPT_PTE;

BOOLEAN InitEpt();
