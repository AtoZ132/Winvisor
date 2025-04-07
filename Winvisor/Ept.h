#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "Arch.h"
#include "WinvisorUtil.h"


/*
*  Implemented according to the Intel SDM ver. September 2023
*/
#define PML4E_ENTRIES_COUNT 512
#define PML3E_ENTRIES_COUNT 512
#define PML2E_ENTRIES_COUNT 512
#define PML1E_ENTRIES_COUNT 512

// Memory Types
#define MEMORY_TYPE_UNCACHEABLE     0x0
#define MEMORY_TYPE_WRITE_COMBINING 0x1
#define MEMORY_TYPE_WRITE_THROUGH   0x4
#define MEMORY_TYPE_WRITE_PROTECTED 0x5
#define MEMORY_TYPE_WRITE_BACK      0x6
#define MEMORY_TYPE_INVALID         0xFF

#define SIZE_2_MB ((SIZE_T)(512 * PAGE_SIZE))


typedef union _EPTP
{
	struct
	{
		UINT64 memoryType : 3; // 0 = Uncacheable (UC) ; 6 = Write - back(WB) ; others are reserved
		UINT64 eptPageWalkLen : 3; // Value is 1 less than the actual walk length
		UINT64 dirtyAndAccessFlagEnable : 1;
		UINT64 supervisorShadowStackEnforce : 1; // Enables enforcement of access rights for supervisor shadow-stack pages
		UINT64 reserved : 4;
		UINT64 pml4Addr : 36;
		UINT64 reserved2 : 16;
	} Bitfields;
	UINT64 flags;
} EPTP, *PEPTP;

typedef struct _MTRR_RANGE_DESCRIPTOR
{
	UINT64 physicalBaseAddress;
	UINT64 physicalEndAddress;
	UINT8 memoryType;
} MTRR_RANGE_DESCRIPTOR, *PMTRR_RANGE_DESCRIPTOR;

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
		UINT64 hugePage : 1; // Must be 1
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
		UINT64 largePage : 1; // Must be 1
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

typedef struct _INVEPT_DESCRIPTOR 
{
	EPTP eptp;
	UINT64 reserved;
} INVEPT_DESC, *PINVEPT_DESC;

typedef EPT_PML4E EPT_PML4_POINTER, * PEPT_PML4_POINTER;
typedef EPT_PDPTE EPT_PML3_POINTER, * PEPT_PML3_POINTER;
typedef EPT_PDE_LARGE_PAGE EPT_PML2_ENTRY, * PEPT_PML2_ENTRY;
typedef EPT_PDE EPT_PML2_POINTER, * PEPT_PML2_POINTER;
typedef EPT_PTE EPT_PML1_ENTRY, * PEPT_PML1_ENTRY;

typedef struct _EPT_PAGE_TABLE
{
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_POINTER pml4[PML4E_ENTRIES_COUNT];

	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML3_POINTER pml3[PML3E_ENTRIES_COUNT];

	// We're using 2MB pages by default and splitting to 4KB as needed.
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML2_ENTRY pml2[PML3E_ENTRIES_COUNT][PML2E_ENTRIES_COUNT];

	LIST_ENTRY dynamicSplitList;
} EPT_PAGE_TABLE, * PEPT_PAGE_TABLE;


typedef struct _EPT_STATE
{
	MTRR_RANGE_DESCRIPTOR mtrrRangeDesc[9];
	UINT32 numberOfEnabledMemoryRanges;
	PEPTP eptp;
	PEPT_PAGE_TABLE eptPageTable;
} EPT_STATE, * PEPT_STATE;


// EPT cache types
typedef enum CACHE_TYPE 
{
	UC = 0, // Uncachable
	WC = 1, // Write Combine
	WT = 4, // Write Through
	WP = 5, // Write Protected
	WB = 6  // Write back
};


extern UINT64 gGuestMappedArea;


NTSTATUS CheckEptFeatures();
VOID BuildMtrrMap(PEPT_STATE eptState);
VOID setupPml2Entry(PEPT_PML2_ENTRY pml2Entry, UINT64 pageFrameNumber, PEPT_STATE eptState);
PEPT_PAGE_TABLE CreateIdentityPageTable(PEPT_STATE eptState);
PEPTP InitEpt();
