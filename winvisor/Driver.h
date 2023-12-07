#pragma once
#include <ntddk.h>


NTSTATUS DriverUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);