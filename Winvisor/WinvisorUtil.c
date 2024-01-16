#include "WinvisorUtil.h"

UINT64 WvsrPaFromVa(UINT64 virtualAddr)
{
	return MmGetPhysicalAddress(virtualAddr).QuadPart;
}

UINT64 WvsrVaFromPa(UINT64 physicalAddr)
{
	PHYSICAL_ADDRESS pa = { 0 };
	pa.QuadPart = physicalAddr;
	
	return MmGetVirtualForPhysical(pa);
}