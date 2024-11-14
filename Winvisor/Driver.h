#pragma once
#include <ntddk.h>
#include "Vmx.h"

extern PSYSTEM_DATA gSystemData;

NTSTATUS DriverUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);