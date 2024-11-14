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
        KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Could not create symbolic link\n"));
        return ntStatus;
    }

    ntStatus = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(ntStatus))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Could not create device object\n"));
        return ntStatus;
    }

    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) 
    {
        DriverObject->MajorFunction[i] = DriverUnsupported;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;

    // Check for vmx support
    ntStatus = CheckVmxSupport();
    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    // Initialize VM structures
    ntStatus = WvsrInitVm();
    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Vmx mode turn on!\n"));

    ntStatus = STATUS_SUCCESS;
    for (int i = 0; i < CPU_COUNT; i++)
    {
        WvsrStartVm(i, &ntStatus);
        if (!NT_SUCCESS(ntStatus))
        {
            DeallocSystemData(gSystemData);
            return ntStatus;
        }
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Driver Loaded!\n"));

    return ntStatus;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) 
{
    UNICODE_STRING dosDeviceName;

    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\WinvisorDevice");
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);

    WvsrStopVm();
    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Vmx mode turn off!\n"));
    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[*] Driver Unloaded!\n"));
}

NTSTATUS DriverUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp) 
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, "[-] Unsupported Call: %d\n", Irp->Type));
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}