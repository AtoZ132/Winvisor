#include "Driver.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
    NTSTATUS        ntStatus;
    UNICODE_STRING  deviceName;    
    UNICODE_STRING  dosDeviceName;  
    PDEVICE_OBJECT  deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, L"\\Device\\WinvisorDevice");
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\WinvisorDevice");
    
    ntStatus = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(ntStatus)) 
    {
        DbgPrint("[-] Could not create symbolic link");
        return ntStatus;
    }

    ntStatus = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrint("[-] Could not create device object");
        return ntStatus;
    }

    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) 
    {
        DriverObject->MajorFunction[i] = DriverUnsupported;
    }

    DriverObject->DriverUnload = DriverUnload;



    DbgPrint("[*] Driver Loaded!");

    return ntStatus;
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) 
{

    UNICODE_STRING dosDeviceName;

    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\WinvisorDevice");
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("[*] Driver Unloaded!");
}

NTSTATUS DriverUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp) 
{

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    DbgPrint("[-] Unsupported Call: %d", Irp->Type);

    return STATUS_SUCCESS;
}