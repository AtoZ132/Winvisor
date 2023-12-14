#include "vmx.h"

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
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] unsupported vendor\n"));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check if vm extensions are supported
	__cpuid(cpuInfo, 1);
	if (cpuInfo[2] & 0x20 == 0) 
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[-] vmx is unsupported\n"));
		return STATUS_NOT_SUPPORTED;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, ("[+] vmx is supported\n"));

	return STATUS_SUCCESS;
}