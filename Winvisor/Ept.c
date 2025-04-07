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
	PMTRR_RANGE_DESCRIPTOR mtrrRangeDesc = NULL;
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

VOID setupPml2Entry(PEPT_PML2_ENTRY pml2Entry, UINT64 pageFrameNumber, PEPT_STATE eptState)
{
	UINT64 addressOfPage;
	UINT64 currentMtrrRange;
	UINT64 targetMemoryType = MEMORY_TYPE_WRITE_BACK;

	pml2Entry->Bitfields.physicalAddress = pageFrameNumber;
	addressOfPage = pageFrameNumber * SIZE_2_MB;

	if (pageFrameNumber == 0) 
	{
		pml2Entry->Bitfields.memoryType = MEMORY_TYPE_UNCACHEABLE;
		return;
	}

	for (currentMtrrRange = 0; currentMtrrRange < eptState->numberOfEnabledMemoryRanges; currentMtrrRange++)
	{
		if ((addressOfPage <= eptState->mtrrRangeDesc[currentMtrrRange].physicalEndAddress) &&
			((addressOfPage + SIZE_2_MB - 1) >= eptState->mtrrRangeDesc[currentMtrrRange].physicalBaseAddress))
		{
			targetMemoryType = eptState->mtrrRangeDesc[currentMtrrRange].memoryType;

			// Uncacheable takes precedence - chapter 12.11.4.1
			if (targetMemoryType == MEMORY_TYPE_UNCACHEABLE)
			{
				break;
			}
		}
	}

	pml2Entry->Bitfields.memoryType = targetMemoryType;
}

PEPT_PAGE_TABLE CreateIdentityPageTable(PEPT_STATE eptState)
{
	PHYSICAL_ADDRESS maxPhyAddr = { 0 };
	PEPT_PAGE_TABLE pageTable;
	EPT_PML3_POINTER pml3Template;
	EPT_PML2_ENTRY largePageTemplate;
	UINT32 entryIndex;
	UINT32 pml2EntryIndex;

	maxPhyAddr.QuadPart = MAXULONG64;

	pageTable = MmAllocateContiguousMemory((sizeof(EPT_PAGE_TABLE) / PAGE_SIZE) * PAGE_SIZE, maxPhyAddr);
	if (!pageTable)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to allocate ept page table\n"));
		return NULL;
	}
	RtlZeroMemory(pageTable, sizeof(EPT_PAGE_TABLE));

	InitializeListHead(&pageTable->dynamicSplitList);
	
	pageTable->pml4[0].Bitfields.physicalAddress = (UINT64)WvsrPaFromVa(&pageTable->pml3[0]) / PAGE_SIZE;
	pageTable->pml4[0].Bitfields.read = 1;
	pageTable->pml4[0].Bitfields.write = 1;
	pageTable->pml4[0].Bitfields.execute = 1;

	pml3Template.flags = 0;
	pml3Template.Bitfields.read = 1;
	pml3Template.Bitfields.write = 1;
	pml3Template.Bitfields.execute = 1;
	
	// Setup all the 512 pml3 entries to rwx for the mapping
	__stosq((PULONG64)&pageTable->pml3[0], pml3Template.flags, PML3E_ENTRIES_COUNT);

	for (entryIndex = 0; entryIndex < PML2E_ENTRIES_COUNT; entryIndex++)
	{
		pageTable->pml3[entryIndex].Bitfields.physicalAddress = (UINT64)WvsrPaFromVa(&pageTable->pml2[entryIndex][0]) / PAGE_SIZE;
	}

	largePageTemplate.flags = 0;
	largePageTemplate.Bitfields.read = 1;
	largePageTemplate.Bitfields.write = 1;
	largePageTemplate.Bitfields.execute = 1;
	largePageTemplate.Bitfields.largePage = 1;

	// Setup 512 * 512 pml2 entries
	__stosq((PULONG64)&pageTable->pml2[0], largePageTemplate.flags, PML3E_ENTRIES_COUNT * PML2E_ENTRIES_COUNT);

	for (entryIndex = 0; entryIndex < PML3E_ENTRIES_COUNT; entryIndex++)
	{
		for (pml2EntryIndex = 0; pml2EntryIndex < PML2E_ENTRIES_COUNT; pml2EntryIndex++)
		{
			setupPml2Entry(&pageTable->pml2[entryIndex][pml2EntryIndex], (entryIndex * PML3E_ENTRIES_COUNT) + pml2EntryIndex, eptState);
		}
	}

	return pageTable;
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
