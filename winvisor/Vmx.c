#include "Vmx.h"

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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] unsupported vendor\n")));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check if vm extensions are supported
	__cpuid(cpuInfo, 1);
	if (cpuInfo[2] & 0x20 == 0) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] vmx is unsupported\n")));
		return STATUS_NOT_SUPPORTED;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[+] vmx is supported\n")));

	// Check IA32_FEATURE_CONTROL msr lock bit 0 and bit 2 for vmxon support outside SMX
	ULONGLONG ia32_feature_control = __readmsr(IA32_FEATURE_CONTROL);
	if (!(ia32_feature_control & IA32_FEATURE_CONTROL_LOCK_BIT))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] IA32_FEATURE_CONTROL lock bit 0 is not set!\n")));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check bit 1
	if (!(ia32_feature_control & IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] IA32_FEATURE_CONTROL vmxon outside smx bit 2 is not set!\n")));
		return STATUS_NOT_SUPPORTED;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[+] IA32_FEATURE_CONTROL is all set\n")));


	return STATUS_SUCCESS;
}

BOOLEAN VmxonOperation()
{
	UINT64 vmcsRegionPhysical = InitVmxonRegion();
	if (vmcsRegionPhysical == NULL) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] Failed to init vmcs region\n")));
		return FALSE;
	}

	int status = __vmx_on(vmcsRegionPhysical);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] vmxon failed with status: %d\n", status)));
		return FALSE;
	}

	return TRUE;
}

/*
*  On success, returns a pointer to the physical address of the vmcs region.
*  On error, returns null
*/
UINT64 InitVmxonRegion()
{
	PVMCS_REGION pVmcsRegion = NULL;
	PHYSICAL_ADDRESS maxPhysicalAddress = { 0 };
	IA32_VMX_BASIC_MSR vmxBasicMsr = { 0 };
	vmxBasicMsr.rawMsr = __readmsr(IA32_VMX_BASIC);
	maxPhysicalAddress.QuadPart = MAXULONG64;

	pVmcsRegion = (PVMCS_REGION)MmAllocateContiguousMemory(sizeof(VMCS_REGION), maxPhysicalAddress);
	if (!pVmcsRegion) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] Failed to allocate vmcs region\n")));
		return NULL;
	}
	RtlZeroMemory(pVmcsRegion,sizeof(VMCS_REGION));
	pVmcsRegion->vmcsRevisionId = (UINT32)vmxBasicMsr.Bitfield.revisionId;

	return MmGetPhysicalAddress(pVmcsRegion).QuadPart;
}

VOID DeallocVmxonRegion(UINT64 vmcsRegionPhysical) 
{
	PHYSICAL_ADDRESS physicalAddr = { 0 };
	physicalAddr.QuadPart = vmcsRegionPhysical;
	PVOID vmcsRegionVirtual = MmGetVirtualForPhysical(physicalAddr);

	MmFreeContiguousMemory(vmcsRegionVirtual);
}
