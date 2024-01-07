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
BOOLEAN VmxonOperation();
UINT64 InitVmxonRegion();
VOID DeallocVmxonRegion(UINT64 vmcsRegionPhysical);