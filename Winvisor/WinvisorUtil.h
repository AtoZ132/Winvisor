#pragma once
#include <ntddk.h>

#define WVSR_TAG 'rsvW'

UINT64* WvsrPaFromVa(UINT64* virtualAddr);
UINT64* WvsrVaFromPa(UINT64* physicalAddr);
