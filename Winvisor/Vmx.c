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

BOOLEAN VmptrldOp(UINT64* vmcsPhysical) 
{
	int status = __vmx_vmptrld(&vmcsPhysical);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmptrld failed with status: %d\n", status));
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

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, 
		"[*] SystemData initialized, addr: %p\n", systemData));
	return TRUE;
}

VOID DeallocSystemData(PSYSTEM_DATA systemData)
{
	DeallocVmcsRegion(systemData->vmxonRegion);
	DeallocVmcsRegion(systemData->vmcsRegion);
}

BOOLEAN WvsrRunVm() 
{
#if UNICORE == 1
	int processorCount = 1;
#else
	int processorCount = 3;
#endif
	gSystemData = (PSYSTEM_DATA)ExAllocatePoolWithTag(NonPagedPool, processorCount * sizeof(SYSTEM_DATA), WVSR_TAG);
	if (gSystemData == NULL)
	{
		return FALSE;
	}
	for (int i = 0; i < processorCount; i++)
	{
		KeSetSystemAffinityThread(1 << i); // Schedule the i-th logic processor
		if (AllocSystemData(&gSystemData[i]) == FALSE)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Allocation failed for core %d\n", i));
			return FALSE;
		}
		if (VmxonOp(WvsrPaFromVa((&gSystemData[i])->vmxonRegion)) == FALSE)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmxon failed for core %d\n", i));
			return FALSE;
		}
		if (VmptrldOp(WvsrPaFromVa((&gSystemData[i])->vmcsRegion)) == FALSE)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] vmptrld failed for core %d\n", i));
			return FALSE;
		}
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] core %d running in vmx root\n", i));
	}

	return TRUE;
}

VOID WvsrStopVm()
{
	for (int i = 0; i < CPU_COUNT; i++)
	{
		KeSetSystemAffinityThread(1 << i); // Schedule the i-th logic processor
		VmxoffOp();
		DeallocSystemData(&gSystemData[i]);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Stopping core %d\n", i));
	}
	ExFreePool(gSystemData);
}