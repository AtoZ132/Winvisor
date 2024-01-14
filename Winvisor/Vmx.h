#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "Arch.h"


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

NTSTATUS CheckVmxSupport();
BOOLEAN VmxonOp(UINT64 vmxonRegionPhysical);
BOOLEAN VmptrldOp(UINT64 vmcsPhysical);
VOID VmxoffOp();
UINT64 InitVmcsRegion();
VOID DeallocVmcsRegion(UINT64 vmcsRegionPhysical);
