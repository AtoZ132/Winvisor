#include "Ept.h"


NTSTATUS CheckEptFeatures()
{
	IA32_MTRR_DEF_TYPE_MSR mtrrDefType = { 0 };

	mtrrDefType.flags = __readmsr(IA32_MTRR_DEF_TYPE);

	if (!mtrrDefType.Bitfield.mtrrEnable)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] mtrr dynamic ranges feature not supported"));
		return STATUS_NOT_SUPPORTED;
	}

	return STATUS_SUCCESS;
}


VOID BuildMtrrMap(PEPT_STATE eptState)
{
	IA32_MTRRCAP_MSR mtrrCap = { 0 };
	IA32_MTRR_PHYSBASE_MSR currentPhysBase = { 0 };
	IA32_MTRR_PHYSMASK_MSR currentPhysMask = { 0 };
	PMTRR_RANGE_DESCRIPTOR mtrrRangeDesc;
	UINT32 currentReg;
	UINT32 numOfBitsInMask;

	mtrrCap.flags = __readmsr(IA32_MTRRCAP);

	for (currentReg = 0; currentReg < mtrrCap.Bitfield.vcnt; currentReg++)
	{
		currentPhysBase.flags = __readmsr(IA32_MTRR_PHYSBASE0 + (currentReg * 2));
		currentPhysMask.flags = __readmsr(IA32_MTRR_PHYSMASK0 + (currentReg * 2));

		if (currentPhysMask.Bitfield.valid)
		{
			mtrrRangeDesc = &eptState->mtrrRangeDesc[eptState->numberOfEnabledMemoryRanges++];
			mtrrRangeDesc->physicalBaseAddress = currentPhysBase.Bitfield.physBase * PAGE_SIZE;

			BitScanForward64(&numOfBitsInMask, currentPhysMask.Bitfield.physMask * PAGE_SIZE);

			mtrrRangeDesc->physicalEndAddress = mtrrRangeDesc->physicalBaseAddress + ((1ULL << numOfBitsInMask) - 1ULL);
			mtrrRangeDesc->memoryType = (UINT8)currentPhysBase.Bitfield.type;

			// Free the range if it's Write-back
			if (mtrrRangeDesc->memoryType == MEMORY_TYPE_WRITE_BACK)
			{
				eptState->numberOfEnabledMemoryRanges--;
			}
		}
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "MTRR Range: Base=0x%llx End=0x%llx Type=0x%x",
			mtrrRangeDesc->physicalBaseAddress, mtrrRangeDesc->physicalEndAddress, mtrrRangeDesc->memoryType));
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Total MTRR Ranges Committed: %d", eptState->numberOfEnabledMemoryRanges));
}

PEPTP InitEpt()
{
	PAGED_CODE();
	
	PEPTP eptp = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (eptp == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] eptp allocation failed"));
		return NULL;
	}

	RtlZeroMemory(eptp, PAGE_SIZE);
	PEPT_PML4E epml4e = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epml4e == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] epml4e allocation failed"));
		ExFreePool(eptp);
		return NULL;
	}

	RtlZeroMemory(epml4e, PAGE_SIZE);
	PEPT_PDPTE epdpte = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epdpte == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] epdpte allocation failed"));
		ExFreePool(epml4e);
		ExFreePool(eptp);
		return NULL;
	}

	RtlZeroMemory(epdpte, PAGE_SIZE);
	PEPT_PDE epde = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epde == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] epde allocation failed"));
		ExFreePool(epdpte);
		ExFreePool(epml4e);
		ExFreePool(eptp);
		return NULL;
	}
	
	RtlZeroMemory(epde, PAGE_SIZE);
	PEPT_PTE epte = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epte == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] epte allocation failed"));
		ExFreePool(epde);
		ExFreePool(epdpte);
		ExFreePool(epml4e);
		ExFreePool(eptp);
		return NULL;
	}

	RtlZeroMemory(epte, PAGE_SIZE);

	// Alloc a few pages to test stuff before actually implementing EPT as planned
	const int numOfPages = 10;
	UINT64 GuestTestPages = ExAllocatePoolWithTag(NonPagedPool, numOfPages * PAGE_SIZE, WVSR_TAG);

	if (GuestTestPages == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] epte allocation failed"));
		ExFreePool(epte);
		ExFreePool(epde);
		ExFreePool(epdpte);
		ExFreePool(epml4e);
		ExFreePool(eptp);
		return NULL;
	}

	RtlZeroMemory(GuestTestPages, numOfPages * PAGE_SIZE);
	memset(GuestTestPages, 0xf4, numOfPages * PAGE_SIZE);
	gGuestMappedArea = GuestTestPages;
	for (int i = 0; i < numOfPages; i++)
	{
		epte[i].Bitfields.read = 1;
		epte[i].Bitfields.write = 1;
		epte[i].Bitfields.execute = 1;
		epte[i].Bitfields.memoryType = WB;
		epte[i].Bitfields.physicalAddress = WvsrPaFromVa((GuestTestPages + (i * PAGE_SIZE)) / PAGE_SIZE);
	}

	epde->Bitfields.read = 1;
	epde->Bitfields.write = 1;
	epde->Bitfields.execute = 1;
	epde->Bitfields.physicalAddress = ((UINT64)WvsrPaFromVa(epte) / PAGE_SIZE);

	epdpte->Bitfields.read = 1;
	epdpte->Bitfields.write = 1;
	epdpte->Bitfields.execute = 1;
	epdpte->Bitfields.physicalAddress = ((UINT64)WvsrPaFromVa(epde) / PAGE_SIZE);


	epml4e->Bitfields.read = 1;
	epml4e->Bitfields.write = 1;
	epml4e->Bitfields.execute = 1;
	epml4e->Bitfields.physicalAddress = ((UINT64)WvsrPaFromVa(epdpte) / PAGE_SIZE);


	eptp->Bitfields.memoryType = WB;
	eptp->Bitfields.dirtyAndAccessFlagEnable = 1;
	eptp->Bitfields.eptPageWalkLen = 3;
	eptp->Bitfields.pml4Addr = ((UINT64)WvsrPaFromVa(epml4e) / PAGE_SIZE);
	
	return eptp;
}
