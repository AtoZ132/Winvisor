#include "Vmx.h"

// Globals
PSYSTEM_DATA gSystemData;

NTSTATUS CheckVmxSupport() 
{
	char vendorId[13];
	int cpuInfo[4] = { 0 };
	STRING vendorString;
	STRING targetVendorString;

	__cpuid(cpuInfo, 0);
	RtlCopyMemory(vendorId, &cpuInfo[1], 4);
	RtlCopyMemory(vendorId + 4, &cpuInfo[3], 4);
	RtlCopyMemory(vendorId + 8, &cpuInfo[2], 4);
	vendorId[12] = '\0';
	
	RtlInitString(&vendorString,&vendorId[0]);
	RtlInitString(&targetVendorString,"GenuineIntel");

	if (!(RtlEqualString(&vendorString, &targetVendorString, FALSE)))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] unsupported vendor\n"));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check if vm extensions are supported
	__cpuid(cpuInfo, 1);
	if (cpuInfo[2] & 0x20 == 0) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmx is unsupported\n"));
		return STATUS_NOT_SUPPORTED;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] vmx is supported\n"));

	// Check IA32_FEATURE_CONTROL msr lock bit 0 and bit 2 for vmxon support outside SMX
	ULONGLONG ia32_feature_control = __readmsr(IA32_FEATURE_CONTROL);
	if (!(ia32_feature_control & IA32_FEATURE_CONTROL_LOCK_BIT))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] IA32_FEATURE_CONTROL lock bit 0 is not set!\n"));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check bit 2
	if (!(ia32_feature_control & IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] IA32_FEATURE_CONTROL vmxon outside smx bit 2 is not set!\n"));
		return STATUS_NOT_SUPPORTED;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] IA32_FEATURE_CONTROL is all set\n"));


	return STATUS_SUCCESS;
}

/*
* vmxon operation is a per preocessor method and affects only the "current" processor
*/
BOOLEAN VmxonOp(UINT64* vmxonRegionPhysical)
{
	// Set cr4.vmxe bit
	ULONGLONG cr4 = __readcr4();
	cr4 |= (1ULL << 13);
	__writecr4(cr4);

	int status = __vmx_on(&vmxonRegionPhysical);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmxon failed with status: %d\n", status));
		return FALSE;
	}

	return TRUE;
}

BOOLEAN VmptrldOp(UINT64* vmcsPhysicalAddress)
{
	int status = __vmx_vmptrld(&vmcsPhysicalAddress);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmptrld failed with status: %d\n", status));
		return FALSE;
	}
	
	return TRUE;
}

BOOLEAN VmclearOp(UINT64* vmcsPhysicalAddress)
{
	int status = __vmx_vmclear(&vmcsPhysicalAddress);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmclear failed with status: %d\n", status));
		return FALSE;
	}

	return TRUE;
}

/*
* vmxoff operation is a per preocessor method and affects only the "current" processor
*/
VOID VmxoffOp()
{
	__vmx_off();

	// Clear cr4.vmxe bit
	ULONGLONG cr4 = __readcr4();
	cr4 &= ~(1ULL << 13);
	__writecr4(cr4);
}

/*
* To invalidate a single ept pass SINGLE_CONTEXT and the EPTP.
* To invalidate all epts pass GLOBAL CONTEXT and NULL.
*/
VOID VmxInveptOp(int inveptType, EPTP eptp)
{
	switch (inveptType)
	{
	case GLOBAL_CONTEXT:
		InveptOp(GLOBAL_CONTEXT, NULL);
		break;
	case SINGLE_CONTEXT:
	{
		INVEPT_DESC inveptDesc = { eptp, 0 };
		InveptOp(SINGLE_CONTEXT, &inveptDesc);
		break;
	}
	default:
		break;
	}
}

BOOLEAN InitSegmentDescriptor(PUINT8 gdtBase, UINT16 segmentSelector, PSEGMENT_DESCRIPTOR segDesc)
{
	PRAW_SEGMENT_DESCRIPTOR rawSegDesc = { 0 };

	if (!(segDesc))
	{
		return FALSE;
	}

	rawSegDesc = (PRAW_SEGMENT_DESCRIPTOR)(gdtBase + (segmentSelector & ~0x7));
	segDesc->baseAddr = rawSegDesc->baseAddr0 | rawSegDesc->baseAddr1 << 16 | rawSegDesc->baseAddr2 << 24;
	segDesc->segLimit = rawSegDesc->segLimit0 | (rawSegDesc->seglimit1_flags & 0xf) << 16;
	segDesc->flags.flags = rawSegDesc->seglimit1_flags & 0xf0;
	segDesc->accessByte.flags = rawSegDesc->accessByte;

	if (segDesc->flags.Bitfield.G)
	{
		segDesc->segLimit = (segDesc->segLimit << 12) + 0xfff;
	}

	if (!(segDesc->accessByte.Bitfield.S))
	{
		UINT64 highAddr = *(PUINT64)((PUINT8)rawSegDesc + 8);
		segDesc->baseAddr = (segDesc->baseAddr & 0xffffffff) | (highAddr << 32);
	}

	return TRUE;
}

BOOLEAN SetupGuestSelectorFields(PUINT8 gdtBase, UINT16 segmentSelector, UINT16 segmentSelectorIndex)
{
	SEGMENT_DESCRIPTOR segDesc = { 0 };

	if (!(InitSegmentDescriptor(gdtBase, segmentSelector, &segDesc)))
	{
		return FALSE;
	}

	__vmx_vmwrite(GUEST_ES_LIMIT + segmentSelectorIndex * 2, segDesc.segLimit);
	__vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS + segmentSelectorIndex * 2, segDesc.accessByte.flags);
	__vmx_vmwrite(GUEST_ES_SELECTOR + segmentSelectorIndex * 2, segmentSelector);
	__vmx_vmwrite(GUEST_ES_BASE + segmentSelectorIndex * 2, segDesc.baseAddr);

	return TRUE;
}

BOOLEAN SetupVmcs()
{
	// 27.2.3: In the selector field for each of CS, SS, DS, ES, FS, GS, and TR, 
	// the RPL (bits 1:0) and the TI flag (bit 2) must be 0.
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCS() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSS() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDS() & 0xF8);
	__vmx_vmwrite(HOST_ES_SELECTOR, GetES() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFS() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGS() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTR() & 0xF8);

	// 27.3.1.5 "VMCS link pointer. The following checks apply if the field contains a value other than 
	// FFFFFFFF_FFFFFFFFH" related to VMCS shadowing
	__vmx_vmwrite(VMCS_LINK_POINTER_FULL, ~0ULL);

	PUINT8 gdtBase = GetGDTBase();
	if (!(SetupGuestSelectorFields(gdtBase, ES, GetES())) ||
		!(SetupGuestSelectorFields(gdtBase, CS, GetCS())) ||
		!(SetupGuestSelectorFields(gdtBase, SS, GetSS())) ||
		!(SetupGuestSelectorFields(gdtBase, DS, GetDS())) ||
		!(SetupGuestSelectorFields(gdtBase, FS, GetFS())) ||
		!(SetupGuestSelectorFields(gdtBase, GS, GetGS())) ||
		!(SetupGuestSelectorFields(gdtBase, LDTR, GetLDTR())) ||
		!(SetupGuestSelectorFields(gdtBase, TR, GetTR())))
	{
		return FALSE;
	}



	return TRUE;
}

/*
*  On success, returns a pointer to the virtual address of the vmcs region.
*  On error, returns null
*/
UINT64* InitVmcsRegion()
{
	PVMCS_REGION pVmcsRegion = NULL;
	PHYSICAL_ADDRESS maxPhysicalAddress = { 0 };
	IA32_VMX_BASIC_MSR vmxBasicMsr = { 0 };
	vmxBasicMsr.flags = __readmsr(IA32_VMX_BASIC);
	maxPhysicalAddress.QuadPart = MAXULONG64;

	pVmcsRegion = (PVMCS_REGION)MmAllocateContiguousMemory(sizeof(VMCS_REGION), maxPhysicalAddress);
	if (!pVmcsRegion) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Failed to allocate vmcs region\n"));
		return NULL;
	}
	RtlZeroMemory(pVmcsRegion, sizeof(VMCS_REGION));
	pVmcsRegion->vmcsRevisionId = (UINT32)vmxBasicMsr.Bitfield.revisionId;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF,
		"[*] vmcs region initialized, addr: %p, revision: %d\n", pVmcsRegion, pVmcsRegion->vmcsRevisionId));

	return pVmcsRegion;
}

VOID DeallocVmcsRegion(UINT64* vmcsRegion) 
{
	MmFreeContiguousMemory(vmcsRegion);
}

BOOLEAN AllocSystemData(PSYSTEM_DATA systemData) 
{
	systemData->vmxonRegion = InitVmcsRegion();
	if (!(systemData->vmxonRegion))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmxon region init failed\n"));
		return FALSE;
	}

	systemData->vmcsRegion = InitVmcsRegion();
	if (!(systemData->vmcsRegion))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmcs region init failed\n"));
		return FALSE;
	}
	
	systemData->eptp = InitEpt();
	if (!(systemData->eptp))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] ept init failed\n"));
		return FALSE;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, 
		"[*] SystemData initialized, addr: %p\n", systemData));

	return TRUE;
}

VOID DeallocSystemData(PSYSTEM_DATA systemData)
{
	DeallocVmcsRegion(systemData->vmxonRegion);
	DeallocVmcsRegion(systemData->vmcsRegion);
}

NTSTATUS WvsrInitVm() 
{
	gSystemData = (PSYSTEM_DATA)ExAllocatePoolWithTag(NonPagedPool, CPU_COUNT * sizeof(SYSTEM_DATA), WVSR_TAG);
	if (gSystemData == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	for (int i = 0; i < CPU_COUNT; i++)
	{
		// Schedule the i-th logic processor
		KeSetSystemAffinityThread(1 << i);

		// Allocate and init VM resources
		if (!(AllocSystemData(&gSystemData[i])))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Allocation failed for core %d\n", i));
			return STATUS_UNSUCCESSFUL;
		}
		if (!(VmxonOp(WvsrPaFromVa((&gSystemData[i])->vmxonRegion))))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmxon failed for core %d\n", i));
			return STATUS_UNSUCCESSFUL;
		}
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] core %d running in vmx root\n", i));
	}

	return STATUS_SUCCESS;
}

VOID WvsrStartVm(UINT32 processorId, NTSTATUS* ntStatus)
{
	UINT64 status = 0;

	KeSetSystemAffinityThread(1 << processorId);

	// Enter "Inactive, Not Current, Clear" state (see Intel SDM Sep.2023 Figure 25-1)
	if (!(VmclearOp(WvsrPaFromVa((&gSystemData[processorId])->vmcsRegion))))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmclear failed for core %d\n", processorId));
		return STATUS_UNSUCCESSFUL;
	}

	// Enter "Active, Current, Clear" state (see Intel SD Sep.2023 Figure 25-1)
	if (!(VmptrldOp(WvsrPaFromVa((&gSystemData[processorId])->vmcsRegion))))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmptrld failed for core %d\n", processorId));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Launching core %d\n", processorId));
	__vmx_vmlaunch();
		
	__vmx_vmread(VM_INSTRUCTION_ERROR, &status);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Error Launching core %d\n Error: %llx\n", processorId, status));

	*ntStatus = STATUS_UNSUCCESSFUL;
}

VOID WvsrStopVm()
{
	for (int i = 0; i < CPU_COUNT; i++)
	{
		// Schedule the i-th logic processor
		KeSetSystemAffinityThread(1 << i); 
		VmxoffOp();
		DeallocSystemData(&gSystemData[i]);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Stopping core %d\n", i));
	}
	ExFreePool(gSystemData);
}
