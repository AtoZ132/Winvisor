#include <iostream>
#include <string>
#include <vector>
#include <conio.h>
#include <Windows.h>
#include <intrin.h>

std::string GetCpuVendor()
{
    int cpuInfo[4] = { 0 };
    char vendorString[13] = { 0 };

    // Call CPUID with EAX=0 to get vendor string
    __cpuid(cpuInfo, 0);

    // Copy vendor string from EBX, EDX, ECX
    memcpy(vendorString, &cpuInfo[1], 4);      // EBX
    memcpy(vendorString + 4, &cpuInfo[3], 4);  // ECX
    memcpy(vendorString + 8, &cpuInfo[2], 4);  // EDX

    return std::string(vendorString);
}

void TestCpuid()
{
    int cpuInfo[4] = { 0 };

    // Test various CPUID leaves
    for (int i = 0; i <= 5; i++)
    {
        __cpuid(cpuInfo, i);
        printf("CPUID Leaf %d: EAX=%08X, EBX=%08X, ECX=%08X, EDX=%08X\n",
            i, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    }
}

int main()
{
    std::string cpuVendor = GetCpuVendor();
    printf("[*] CPU Vendor: %s\n", cpuVendor.c_str());

    if (cpuVendor == "GenuineIntel")
    {
        printf("[*] Processor virtualization technology is VT-x\n");
    }
    else
    {
        printf("[*] This program is not designed for non-VT-x environments!\n");
        return 1;
    }

    printf("\n[*] Running CPUID tests...\n");
    TestCpuid();
    // Open a handle to the hypervisor device
    HANDLE hDevice = CreateFile(
        L"\\\\.\\WinvisorDevice",             
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL); 
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }
    printf("\n[*] Press any key to exit...\n");
    _getch();
    return 0;
}