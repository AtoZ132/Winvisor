#include "Ept.h"


PEPTP InitEpt()
{
	PAGED_CODE();
	
	PEPTP eptp = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (eptp == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] eptp allocation failed"));
		return NULL;
	}

	RtlZeroMemory(eptp, PAGE_SIZE);
	PEPT_PML4E epml4e = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epml4e == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] epml4e allocation failed"));
		ExFreePool(eptp);
		return NULL;
	}

	RtlZeroMemory(epml4e, PAGE_SIZE);
	PEPT_PDPTE epdpte = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epdpte == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] epdpte allocation failed"));
		ExFreePool(epml4e);
		ExFreePool(eptp);
		return NULL;
	}

	RtlZeroMemory(epdpte, PAGE_SIZE);
	PEPT_PDE epde = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epde == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] epde allocation failed"));
		ExFreePool(epdpte);
		ExFreePool(epml4e);
		ExFreePool(eptp);
		return NULL;
	}
	
	RtlZeroMemory(epde, PAGE_SIZE);
	PEPT_PTE epte = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (epte == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] epte allocation failed"));
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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] epte allocation failed"));
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
