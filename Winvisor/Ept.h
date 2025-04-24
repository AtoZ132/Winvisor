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

// Index of the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)

// Index of the 2nd paging structure (2MB)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)

// Index of the 3rd paging structure (1GB)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)

// Index of the 4th paging structure (512GB)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)


typedef union _EPTP
{
	struct
	{
		UINT64 memoryType : 3;

		// Value is 1 less than the actual walk length
		UINT64 eptPageWalkLen : 3; 
		UINT64 dirtyAndAccessFlagEnable : 1;

		// Enables enforcement of access rights for supervisor shadow-stack pages
		UINT64 supervisorShadowStackEnforce : 1;
		UINT64 reserved : 4;
		UINT64 pml4Addr : 36;
		UINT64 reserved2 : 16;
	} Bitfields;
	UINT64 flags;
} EPTP, * PEPTP;

typedef struct _MTRR_RANGE_DESCRIPTOR
{
	UINT64 physicalBaseAddress;
	UINT64 physicalEndAddress;
	UINT8 memoryType;
} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;

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
		UINT64 userModeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 12;
	} Bitfields;
	UINT64 flags;
} EPT_PML4E, * PEPT_PML4E;

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
		
		// Must be 1
		UINT64 hugePage : 1;
		UINT64 accessedFlag : 1;
		UINT64 dirtyFlag : 1;
		UINT64 userModeExecute : 1;
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
		UINT64 suppressVE : 1;
	} Bitfields;
	UINT64 flags;
} EPT_PDPTE_HUGE_PAGE, * PEPT_PDPTE_HUGE_PAGE;

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
		UINT64 userModeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 12;
	} Bitfields;
	UINT64 flags;
} EPT_PDPTE, * PEPT_PDPTE;

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
		
		// Must be 1
		UINT64 largePage : 1;
		UINT64 accessedFlag : 1;
		UINT64 dirtyFlag : 1;
		UINT64 userModeExecute : 1;
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
		UINT64 suppressVE : 1;
	} Bitfields;
	UINT64 flags;
} EPT_PDE_LARGE_PAGE, * PEPT_PDE_LARGE_PAGE;

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
		UINT64 userModeExecute : 1;
		UINT64 ignored2 : 1;
		UINT64 physicalAddress : 36;
		UINT64 reserved2 : 4;
		UINT64 ignored3 : 12;
	} Bitfields;
	UINT64 flags;
} EPT_PDE, * PEPT_PDE;

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
		UINT64 userModeExecute : 1;
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
		UINT64 suppressVE : 1;
	} Bitfields;
	UINT64 flags;
} EPT_PTE, * PEPT_PTE;

typedef struct _INVEPT_DESC
{
	UINT64 eptp;
	UINT64 reserved;
} INVEPT_DESC, * PINVEPT_DESC;



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

typedef struct _EPT_DYNAMIC_SPLIT
{
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY pml1[PML1E_ENTRIES_COUNT];

	union
	{
		PEPT_PML2_ENTRY pml2Entry;
		PEPT_PML2_POINTER pml2Pointer;
	};

	LIST_ENTRY dynamicSplitList;
}EPT_DYNAMIC_SPLIT, * PEPT_DYNAMIC_SPLIT;


typedef struct _EPT_STATE
{
	MTRR_RANGE_DESCRIPTOR mtrrRangeDesc[9];
	UINT32 numberOfEnabledMemoryRanges;
	EPTP eptp;
	PEPT_PAGE_TABLE eptPageTable;
	PUINT64 preAllocatedBuffer;
} EPT_STATE, * PEPT_STATE;

typedef union _EPT_VIOLATION_EXIT_QUAL
{
	struct
	{
		UINT64 causeRead : 1;
		UINT64 causeWrite : 1;
		UINT64 causeExecute : 1;
		UINT64 eptReadable : 1;
		UINT64 eptWriteable : 1;
		UINT64 eptExecutable : 1;
		UINT64 eptExecutableForUserMode : 1;
		UINT64 validGuestLinearAddress : 1;
		UINT64 causeAddressTranslation : 1;

		/*
		* This bit is 0 if the linear address is a supervisor-mode linear address and
		* 1 if it is a user-mode linear address.
		*/
		UINT64 userModeLinearAddress : 1;

		/*
		* This bit is 0 if paging translates the linear address to a read-only page and
		* 1 if it translates to a read/write page.
		*/
		UINT64 readableWriteablePage : 1;

		/*
		* This bit is 0 if paging translates the linear address to an executable page and
		* 1 if it translates to an execute-disable page.
		*/
		UINT64 executeDisablePage : 1;

		// NMI unblocking due to IRET
		UINT64 nmiUnblocking : 1;
		UINT64 shadowStackAccess : 1;

		/*
		* If supervisor shadow-stack control is enabled (by setting bit 7 of EPTP),
		* this bit is the same as bit 60 in the EPT
		* paging-structure entry that maps the page of the guest-physical address of the access causing the EPT violation.
		*/
		UINT64 supervisorShadowStack : 1;
		UINT64 guestPagingVerification : 1;
		UINT64 asynchronousToInstruction : 1;
		UINT64 reserved : 47;
	} Bitfield;
	UINT64 flags;
} EPT_VIOLATION_EXIT_QUAL, * PEPT_VIOLATION_EXIT_QUAL;


extern void inline InvokeVmcall(UINT64 vmcallNumber, UINT64 param1, UINT64 param2);


VOID NotifyInvalidateAllEpt(UINT64 context);
VOID InvalidateEptByVmcall(UINT64 context);
NTSTATUS CheckEptFeatures();
VOID EptBuildMtrrMap(PEPT_STATE eptState);
VOID EptSetupPml2Entry(PEPT_PML2_ENTRY pml2Entry, UINT64 pageFrameNumber, PEPT_STATE eptState);
PEPT_PAGE_TABLE EptCreateIdentityPageTable(PEPT_STATE eptState);
PEPT_PML2_ENTRY EptGetPml2Entry(PEPT_PAGE_TABLE pageTable, UINT64 physicalAddress);
PEPT_PML1_ENTRY EptGetPml1Entry(PEPT_PAGE_TABLE pageTable, UINT64 physicalAddress);
BOOLEAN EptSplitLargePage(PEPT_STATE eptState, UINT64 physicalAddress);
BOOLEAN EptVmxRootModePageHook(PEPT_STATE eptState, PVOID targetFunction, BOOLEAN hasLaunched);
BOOLEAN EptPageHook(PEPT_STATE eptState, PVOID targetFunction, BOOLEAN hasLaunched);
BOOLEAN EptHandleEptViolation(UINT64 exitQualification, PEPT_STATE eptState, UINT64 guestPhysicalAddress);
BOOLEAN InitializeEptState(PEPT_STATE eptState);
