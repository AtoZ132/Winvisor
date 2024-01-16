#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "Arch.h"
#include "WinvisorUtil.h"


/*
* vmcs_revision_id - 
*	Bits 30:0: VMCS revision identifier
*	Bit 31: shadow-VMCS indicator
*/
typedef struct _VMCS_REGION
{
	UINT32 vmcsRevisionId;
	UINT32 vmxAbortIndicator;
	UINT8  vmcsData[PAGE_SIZE - 8];
} VMCS_REGION, *PVMCS_REGION;

/*
* the vmcs regions hold the virtual address to the regions
*/
typedef struct _SYSTEM_DATA 
{
	PVMCS_REGION vmxonRegion;
	PVMCS_REGION vmcsRegion;
} SYSTEM_DATA, *PSYSTEM_DATA;

NTSTATUS CheckVmxSupport();
BOOLEAN VmxonOp(UINT64 vmxonRegionPhysical);
BOOLEAN VmptrldOp(UINT64 vmcsPhysical);
VOID VmxoffOp();
UINT64 InitVmcsRegion();
VOID DeallocVmcsRegion(UINT64 vmcsRegionPhysical);
BOOLEAN AllocSystemData();
VOID DeallocSystemData();
PSYSTEM_DATA GetSystemData();