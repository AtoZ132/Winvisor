#include "Ept.h"


VOID NotifyInvalidateAllEpt(UINT64 context)
{
	// Notify all CPUs
	KeIpiGenericCall(InvalidateEptByVmcall, context);
}

VOID InvalidateEptByVmcall(UINT64 context)
{
	InvokeVmcall(VMCALL_INVEPT, context, NULL);
}

NTSTATUS CheckEptFeatures()
{
	IA32_MTRR_DEF_TYPE_MSR mtrrDefType = { 0 };

	mtrrDefType.flags = __readmsr(IA32_MTRR_DEF_TYPE);

	if (!mtrrDefType.Bitfield.mtrrEnable)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] MTRR dynamic ranges feature not supported"));
		return STATUS_NOT_SUPPORTED;
	}

	return STATUS_SUCCESS;
}

VOID EptBuildMtrrMap(PEPT_STATE eptState)
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

VOID EptSetupPml2Entry(PEPT_PML2_ENTRY pml2Entry, UINT64 pageFrameNumber, PEPT_STATE eptState)
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

PEPT_PAGE_TABLE EptCreateIdentityPageTable(PEPT_STATE eptState)
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
			EptSetupPml2Entry(&pageTable->pml2[entryIndex][pml2EntryIndex], (entryIndex * PML3E_ENTRIES_COUNT) + pml2EntryIndex, eptState);
		}
	}

	return pageTable;
}

PEPT_PML2_ENTRY EptGetPml2Entry(PEPT_PAGE_TABLE pageTable, UINT64 physicalAddress)
{
	UINT64 pml3Index, pml2Index, pml4Index;
	PEPT_PML2_ENTRY pml2Entry;

	pml2Index = ADDRMASK_EPT_PML2_INDEX(physicalAddress);
	pml3Index = ADDRMASK_EPT_PML3_INDEX(physicalAddress);
	pml4Index = ADDRMASK_EPT_PML4_INDEX(physicalAddress);

	if (pml4Index > 0)
	{
		return NULL;
	}

	pml2Entry = &pageTable->pml2[pml3Index][pml2Index];

	return pml2Entry;
}

PEPT_PML1_ENTRY EptGetPml1Entry(PEPT_PAGE_TABLE pageTable, UINT64 physicalAddress)
{
	UINT64 pml3Index, pml2Index, pml4Index;
	PEPT_PML2_ENTRY pml2Entry;
	PEPT_PML1_ENTRY pml1Entry;
	PEPT_PML2_POINTER pml2Ptr;

	pml2Index = ADDRMASK_EPT_PML2_INDEX(physicalAddress);
	pml3Index = ADDRMASK_EPT_PML3_INDEX(physicalAddress);
	pml4Index = ADDRMASK_EPT_PML4_INDEX(physicalAddress);

	if (pml4Index > 0)
	{
		return NULL;
	}

	pml2Entry = &pageTable->pml2[pml3Index][pml2Index];
	if (pml2Entry->Bitfields.largePage)
	{
		return NULL;
	}

	pml2Ptr = (PEPT_PML2_POINTER)pml2Entry;

	pml1Entry = (PEPT_PML1_ENTRY)WvsrPaFromVa((UINT64*)(pml2Ptr->Bitfields.physicalAddress * PAGE_SIZE));
	if (!pml1Entry)
	{
		return NULL;
	}
	pml1Entry = &pml1Entry[ADDRMASK_EPT_PML1_INDEX(physicalAddress)];

	return pml1Entry;
}

BOOLEAN EptSplitLargePage(PEPT_STATE eptState, UINT64 physicalAddress)
{
	PEPT_PML2_ENTRY targetEntry;
	PEPT_DYNAMIC_SPLIT newSplit;
	EPT_PML1_ENTRY pml1EntryTemplate;
	UINT32 entryIndex;
	EPT_PML2_POINTER newPml2Pointer;

	targetEntry = EptGetPml2Entry(eptState->eptPageTable, physicalAddress);
	if (!targetEntry)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Invalid physical address\n"));
		return FALSE;
	}

	// Page is already split
	if (!targetEntry->Bitfields.largePage)
	{
		return TRUE;
	}

	newSplit = (PEPT_DYNAMIC_SPLIT)eptState->preAllocatedBuffer;
	eptState->preAllocatedBuffer = NULL;
	if (!newSplit)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to allocate dynamic split memory\n"));
		return FALSE;
	}
	RtlZeroMemory(newSplit, sizeof(EPT_DYNAMIC_SPLIT));

	pml1EntryTemplate.flags = 0;
	pml1EntryTemplate.Bitfields.read = 1;
	pml1EntryTemplate.Bitfields.write = 1;
	pml1EntryTemplate.Bitfields.execute = 1;

	__stosq((PULONG64)&newSplit->pml1[0], pml1EntryTemplate.flags, PML1E_ENTRIES_COUNT);

	for (entryIndex = 0; entryIndex < PML1E_ENTRIES_COUNT; entryIndex++)
	{
		newSplit->pml1[entryIndex].Bitfields.physicalAddress = 
			((targetEntry->Bitfields.physicalAddress * SIZE_2_MB) / PAGE_SIZE) + entryIndex;
	}

	newPml2Pointer.flags = 0;
	newPml2Pointer.Bitfields.read = 1;
	newPml2Pointer.Bitfields.write = 1;
	newPml2Pointer.Bitfields.execute = 1;
	newPml2Pointer.Bitfields.physicalAddress = (UINT64)WvsrPaFromVa(&newSplit->pml1[0]) / PAGE_SIZE;

	InsertHeadList(&eptState->eptPageTable->dynamicSplitList, &newSplit->dynamicSplitList);

	RtlCopyMemory(targetEntry, &newPml2Pointer, sizeof(newPml2Pointer));

	return TRUE;
}

BOOLEAN EptVmxRootModePageHook(PEPT_STATE eptState, PVOID targetFunction, BOOLEAN hasLaunched)
{
	PUINT64 targetVirtualAddress;
	UINT64 physicalAddress;
	PEPT_PML1_ENTRY targetPage;
	EPT_PML1_ENTRY originalPage;

	targetVirtualAddress = PAGE_ALIGN(targetFunction);
	physicalAddress = (UINT64)WvsrPaFromVa(targetVirtualAddress);
	if (!physicalAddress)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] couldn't map virt to physical!\n"));
		return FALSE;
	}

	if (!EptSplitLargePage(eptState, physicalAddress))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"[-] couldn't split large page at: 0x%llx\n", physicalAddress));
		return FALSE;
	}

	targetPage = EptGetPml1Entry(eptState->eptPageTable, physicalAddress);
	if (!targetPage)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] couldn't get the PML1 entry!\n"));
		return FALSE;
	}

	originalPage = *targetPage;

	originalPage.Bitfields.read = 1;
	originalPage.Bitfields.write = 1;
	originalPage.Bitfields.execute = 0;

	targetPage->flags = originalPage.flags;

	if (hasLaunched)
	{
		NotifyInvalidateAllEpt(eptState->eptp.flags);
	}

	return TRUE;
}

BOOLEAN EptPageHook(PEPT_STATE eptState, PVOID targetFunction, BOOLEAN hasLaunched)
{
	// Pre-allocated buffer hasn't been created yet
	if (!(eptState->preAllocatedBuffer))
	{
		eptState->preAllocatedBuffer = (PUINT64)ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_DYNAMIC_SPLIT), WVSR_TAG);
		if (!(eptState->preAllocatedBuffer))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] pre-allocated buffer allocation failed!\n"));
			return FALSE;
		}
		RtlZeroMemory(eptState->preAllocatedBuffer, sizeof(EPT_DYNAMIC_SPLIT));
	}

	if (hasLaunched)
	{
		InvokeVmcall(VMCALL_EXEC_HOOK_PAGE, eptState, targetFunction);
		NotifyInvalidateAllEpt(eptState->eptp.flags);
		return TRUE;
	}
	else
	{
		if ((EptVmxRootModePageHook(eptState, targetFunction, hasLaunched)))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] Hook placed!\n"));
			return TRUE;
		}
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] page hook failed!\n"));

	return FALSE;
}

BOOLEAN EptHandleEptViolation(UINT64 exitQualification, PEPT_STATE eptState, UINT64 guestPhysicalAddress)
{
	EPT_VIOLATION_EXIT_QUAL eptExitQual = { 0 };
	UINT64 physicalAddress;
	PEPT_PML1_ENTRY pml1Entry;

	eptExitQual.flags = exitQualification;
	physicalAddress = PAGE_ALIGN(guestPhysicalAddress);

	pml1Entry = EptGetPml1Entry(eptState->eptPageTable, physicalAddress);
	if (!pml1Entry)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] In EptHandleEptViolation: failed get the PML1 entry!\n"));
		return FALSE;
	}

	if (!eptExitQual.Bitfield.eptExecutable && eptExitQual.Bitfield.causeExecute)
	{
		pml1Entry->Bitfields.execute = 1;
		InvalidateEptByVmcall(eptState->eptp.flags);

		return FALSE;
	}

	return TRUE;
}

// Organize all the eptState init here
BOOLEAN InitializeEptState(PEPT_STATE eptState)
{
	PEPT_PAGE_TABLE pageTable;
	EPTP eptp = { 0 };
	
	// Init the MTRR map
	EptBuildMtrrMap(eptState);

	// Init the identity page table
	pageTable = EptCreateIdentityPageTable(eptState);
	if (!pageTable)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Ept Init Failed!\n"));
		return FALSE;
	}
	
	eptState->eptPageTable = pageTable;
	
	// Init the ept pointer
	eptp.flags = 0;
	eptp.Bitfields.memoryType = MEMORY_TYPE_WRITE_BACK;
	eptp.Bitfields.dirtyAndAccessFlagEnable = FALSE;
	eptp.Bitfields.eptPageWalkLen = 3;
	eptp.Bitfields.pml4Addr = (UINT64)WvsrPaFromVa(&pageTable->pml4) / PAGE_SIZE;

	eptState->eptp = eptp;

	return TRUE;
}
