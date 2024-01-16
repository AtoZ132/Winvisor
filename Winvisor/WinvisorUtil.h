#pragma once
#include <ntddk.h>


UINT64 WvsrPaFromVa(UINT64 virtualAddr);
UINT64 WvsrVaFromPa(UINT64 physicalAddr);
