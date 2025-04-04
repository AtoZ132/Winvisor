#include "Vmx.h"


PSYSTEM_DATA gSystemData;
UINT64 gGuestMappedArea;

NTSTATUS CheckVmxSupport() 
{
	char vendorId[13];
	int cpuInfo[4] = { 0 };
	STRING vendorString;
	STRING targetVendorString;

	__cpuid(cpuInfo, 0);
	RtlCopyMemory(vendorId, &cpuInfo[1], 4);
	RtlCopyMemory(vendorId + 4, &cpuInfo[3], 4);
	RtlCopyMemory(vendorId + 8, &cpuInfo[2], 4);
	vendorId[12] = '\0';
	
	RtlInitString(&vendorString,&vendorId[0]);
	RtlInitString(&targetVendorString,"GenuineIntel");

	if (!(RtlEqualString(&vendorString, &targetVendorString, FALSE)))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] unsupported vendor\n"));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check if vm extensions are supported
	__cpuid(cpuInfo, 1);
	if (cpuInfo[2] & 0x20 == 0) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmx is unsupported\n"));
		return STATUS_NOT_SUPPORTED;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] vmx is supported\n"));

	// Check IA32_FEATURE_CONTROL msr lock bit 0 and bit 2 for vmxon support outside SMX
	ULONGLONG ia32_feature_control = __readmsr(IA32_FEATURE_CONTROL);
	if (!(ia32_feature_control & IA32_FEATURE_CONTROL_LOCK_BIT))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] IA32_FEATURE_CONTROL lock bit 0 is not set!\n"));
		return STATUS_NOT_SUPPORTED;
	}
	
	// Check bit 2
	if (!(ia32_feature_control & IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] IA32_FEATURE_CONTROL vmxon outside smx bit 2 is not set!\n"));
		return STATUS_NOT_SUPPORTED;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] IA32_FEATURE_CONTROL is all set\n"));

	return STATUS_SUCCESS;
}

/*
* vmxon operation is a per preocessor method and affects only the "current" processor
*/
BOOLEAN VmxonOp(UINT64* vmxonRegionPhysical)
{
	// Set cr4.vmxe bit
	ULONGLONG cr4 = __readcr4();
	cr4 |= (1ULL << 13);
	__writecr4(cr4);

	int status = __vmx_on(&vmxonRegionPhysical);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmxon failed with status: %d\n", status));
		return FALSE;
	}

	return TRUE;
}

BOOLEAN VmptrldOp(UINT64* vmcsPhysicalAddress)
{
	int status = __vmx_vmptrld(&vmcsPhysicalAddress);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmptrld failed with status: %d\n", status));
		return FALSE;
	}
	
	return TRUE;
}

BOOLEAN VmclearOp(UINT64* vmcsPhysicalAddress)
{
	int status = __vmx_vmclear(&vmcsPhysicalAddress);
	if (status)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmclear failed with status: %d\n", status));
		return FALSE;
	}

	return TRUE;
}

/*
* vmxoff operation is a per preocessor method and affects only the "current" processor
*/
VOID VmxoffOp()
{
	__vmx_off();

	// Clear cr4.vmxe bit
	ULONGLONG cr4 = __readcr4();
	cr4 &= ~(1ULL << 13);
	__writecr4(cr4);
}

/*
* To invalidate a single ept pass SINGLE_CONTEXT and the EPTP.
* To invalidate all epts pass GLOBAL CONTEXT and NULL.
*/
VOID VmxInveptOp(int inveptType, EPTP eptp)
{
	switch (inveptType)
	{
	case GLOBAL_CONTEXT:
		InveptOp(GLOBAL_CONTEXT, NULL);
		break;
	case SINGLE_CONTEXT:
	{
		INVEPT_DESC inveptDesc = { eptp, 0 };
		InveptOp(SINGLE_CONTEXT, &inveptDesc);
		break;
	}
	default:
		break;
	}
}

VOID VmResumeErrorHandler()
{
	int errorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmresume failed, error code: %d\n", errorCode));
}

VOID IncrementIp()
{
	UINT64 guestRip = 0;
	UINT32 instructionLen = 0;
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LENGTH, &instructionLen);

	__vmx_vmwrite(GUEST_RIP, guestRip + instructionLen);
}

VOID VmExitCpuidHandler(PREGS regs)
{
	INT32 cpuInfo[4] = { 0 };

	__cpuidex(cpuInfo, (INT32)regs->rax, (INT32)regs->rcx);

	if (regs->rax == CPUID_INFO)
	{
		cpuInfo[2] |= CPUID_HV_PRESENT_BIT;
	}
	else if(regs->rax == CPUID_HV_ID)
	{
		cpuInfo[0] = WVSR_TAG;
	}

	regs->rax = cpuInfo[0];
	regs->rbx = cpuInfo[1];
	regs->rcx = cpuInfo[2];
	regs->rdx = cpuInfo[3];
}

VOID VmExitCrAccessHandler(PREGS regs)
{
	UINT64 exitQualification = 0;
	MOV_CR_ACCESS_QUAL crAccessQual = { 0 };
	PUINT64 pReg = (PUINT64)&regs->rax + crAccessQual.Bitfield.gpReg;

	__vmx_vmread(EXIT_QUALIFICATION, &exitQualification);
	crAccessQual.flags = exitQualification;

	switch (crAccessQual.Bitfield.accessType)
	{
	case MOV_TO_CR:
	{
		switch (crAccessQual.Bitfield.crNumber)
		{
		case 0:
		{
			UINT64 newCr0 = *pReg;
			newCr0 &= __readmsr(IA32_VMX_CR0_FIXED1);
			newCr0 |= __readmsr(IA32_VMX_CR0_FIXED0);
			__vmx_vmwrite(GUEST_CR0, newCr0);
			__vmx_vmwrite(CR0_READ_SHADOW, newCr0);
			break;
		}
		case 4:
		{
			UINT64 newCr4 = *pReg;
			newCr4 &= __readmsr(IA32_VMX_CR4_FIXED1);
			newCr4 |= __readmsr(IA32_VMX_CR4_FIXED0);
			__vmx_vmwrite(GUEST_CR4, newCr4);
			__vmx_vmwrite(CR4_READ_SHADOW, newCr4);
			break;
		}
		case 3:
		{
			// Need to Add TLB invalidation
			__vmx_vmwrite(GUEST_CR3, *pReg & ~(1ULL << 63));
			break;
		}
		default:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] unimplemented mov-to-cr case!\n"));
			KdBreakPoint();
			break;
		}
		break;
	}
	case MOV_FROM_CR:
	{
		switch (crAccessQual.Bitfield.crNumber)
		{
		case 0:
		{
			__vmx_vmread(GUEST_CR0, pReg);
			break;
		}
		case 3:
		{
			__vmx_vmread(GUEST_CR3, pReg);
			break;
		}
		case 4:
		{
			__vmx_vmread(GUEST_CR4, pReg);
			break;
		}
		default:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] unimplemented mov-from-cr case!\n"));
			KdBreakPoint();
			break;
		}
		break;
	}
	default:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] unimplemented!\n"));
		KdBreakPoint();
		break;
	}
	}
}

VOID VmExitMsrReadHandler(PREGS regs)
{
	MSR msr = { 0 };

	if ((regs->rcx > 0 && regs->rcx < 0x00001FFF) ||
		(regs->rcx > 0xC0000000 && regs->rcx < 0xC0001FFF))
	{
		msr.flags = __readmsr(regs->rcx);
		regs->rax = msr.Fields.low;
		regs->rdx = msr.Fields.high;
	}
}

VOID VmExitMsrWriteHandler(PREGS regs)
{
	MSR msr = { 0 };

	if ((regs->rcx > 0 && regs->rcx < 0x00001FFF) ||
		(regs->rcx > 0xC0000000 && regs->rcx < 0xC0001FFF))
	{
		msr.Fields.low = regs->rax;
		msr.Fields.high = regs->rdx;
		__writemsr(regs->rcx, msr.flags);
	}
}

VOID VmExitVmxHandler(PREGS regs) 
{
	UINT64 rflags = 0;
	
	__vmx_vmread(GUEST_RFLAGS, &rflags);
	__vmx_vmwrite(GUEST_RFLAGS, rflags | 0x1); // cf = 1. As per Chapter 31.2 for the VMfailInvalid case.
}

VOID SetupMsrBitmap(UINT64 msrBitmap)
{
	RTL_BITMAP readMsrLowBitmap = { 0 };
	RTL_BITMAP readMsrHighBitmap = { 0 };
	RTL_BITMAP writeMsrLowBitmap = { 0 };
	RTL_BITMAP writeMsrHighBitmap = { 0 };
	
	UINT8* readMsrLow = (UINT8*)msrBitmap;
	UINT8* readMsrHigh = readMsrLow + 1024;
	UINT8* writeMsrLow = readMsrLow + 2048;
	UINT8* writeMsrHigh = readMsrLow + 3072;

	RtlInitializeBitMap(&readMsrLowBitmap, readMsrLow, 1024);
	RtlInitializeBitMap(&readMsrHighBitmap, readMsrHigh, 1024);
	RtlInitializeBitMap(&writeMsrLowBitmap, writeMsrLow, 1024);
	RtlInitializeBitMap(&writeMsrHighBitmap, writeMsrHigh, 1024);

	// For now clear the bitmap so no readmsr/writemsr triggers a vmexit
	// Fill with 0xff to set vm-exit for all read/write msrs or 
	// RtlSetBit / RtlClearBit for specific bits
	RtlFillMemory(readMsrLow, 1024, 0);
	RtlFillMemory(readMsrHigh, 1024, 0);
	RtlFillMemory(writeMsrLow, 1024, 0);
	RtlFillMemory(writeMsrHigh, 1024, 0);
}

BOOLEAN InitSegmentDescriptor(PUINT8 gdtBase, UINT16 segmentSelector, PSEGMENT_DESCRIPTOR segDesc)
{
	PRAW_SEGMENT_DESCRIPTOR rawSegDesc;

	if (!(segDesc))
	{
		return FALSE;
	}

	rawSegDesc = (PRAW_SEGMENT_DESCRIPTOR)(gdtBase + (segmentSelector & ~0x7));
	segDesc->baseAddr = rawSegDesc->baseAddr0 | (rawSegDesc->baseAddr1 << 16) | (rawSegDesc->baseAddr2 << 24);
	segDesc->segLimit = rawSegDesc->segLimit0 | ((rawSegDesc->seglimit1_flags & 0xf) << 16);;
	segDesc->accessRight.flags = rawSegDesc->accessByte | ((rawSegDesc->seglimit1_flags & 0xf0) << 4);

	if (segDesc->accessRight.Bitfield.G)
	{
		segDesc->segLimit = (segDesc->segLimit << 12) + 0xfff;
	}

	if (!(segDesc->accessRight.Bitfield.S))
	{
		UINT64 highAddr = *(PUINT64)((PUINT8)rawSegDesc + 8);
		segDesc->baseAddr = (segDesc->baseAddr & 0xffffffff) | (highAddr << 32);
	}

	return TRUE;
}

BOOLEAN SetupGuestSelectorFields(PUINT8 gdtBase, UINT16 segmentSelectorIndex, UINT16 segmentSelector)
{
	SEGMENT_DESCRIPTOR segDesc = { 0 };

	if (!(InitSegmentDescriptor(gdtBase, segmentSelector, &segDesc)))
	{
		return FALSE;
	}

	UINT32 accessRights = ((PUINT8)&segDesc.accessRight)[0] + (((PUINT8)&segDesc.accessRight)[1] << 12);
	if (!segmentSelector)
	{
		accessRights |= 0x10000;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
		"[*] segDesc: index: %d, segDesc.Limit: %x, accessRights: %x, segDesc.baseAddr: %llx\n", 
		segmentSelectorIndex, segDesc.segLimit, accessRights, segDesc.baseAddr));
	__vmx_vmwrite(GUEST_ES_LIMIT + segmentSelectorIndex * 2, segDesc.segLimit);
	__vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS + segmentSelectorIndex * 2, accessRights);
	__vmx_vmwrite(GUEST_ES_SELECTOR + segmentSelectorIndex * 2, segmentSelector);
	__vmx_vmwrite(GUEST_ES_BASE + segmentSelectorIndex * 2, segDesc.baseAddr);

	return TRUE;
}

UINT32 AdjustVmcsControlField(UINT32 controls, ULONG msrAddr)
{
	MSR msr = { 0 };
	msr.flags = __readmsr(msrAddr);

	controls &= msr.Fields.high;
	controls |= msr.Fields.low;

	return controls;
}

BOOLEAN SetupVmcs(PSYSTEM_DATA systemData)
{
	// 27.2.3: In the selector field for each of CS, SS, DS, ES, FS, GS, and TR, 
	// the RPL (bits 1:0) and the TI flag (bit 2) must be 0.
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCS() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSS() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDS() & 0xF8);
	__vmx_vmwrite(HOST_ES_SELECTOR, GetES() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFS() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGS() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTR() & 0xF8);

	// 27.3.1.5 "VMCS link pointer. The following checks apply if the field contains a value other than 
	// FFFFFFFF_FFFFFFFFH" related to VMCS shadowing
	__vmx_vmwrite(VMCS_LINK_POINTER_FULL, ~0ULL);

	PUINT8 gdtBase = GetGDTBase();
	if (!(SetupGuestSelectorFields(gdtBase, ES, GetES())) ||
		!(SetupGuestSelectorFields(gdtBase, CS, GetCS())) ||
		!(SetupGuestSelectorFields(gdtBase, SS, GetSS())) ||
		!(SetupGuestSelectorFields(gdtBase, DS, GetDS())) ||
		!(SetupGuestSelectorFields(gdtBase, FS, GetFS())) ||
		!(SetupGuestSelectorFields(gdtBase, GS, GetGS())) ||
		!(SetupGuestSelectorFields(gdtBase, LDTR, GetLDTR())) ||
		!(SetupGuestSelectorFields(gdtBase, TR, GetTR())))
	{
		return FALSE;
	}

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
	
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_STATE, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);

	// Setup VM-Execution Controls
	__vmx_vmwrite(PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
		AdjustVmcsControlField(VMX_PRIMARY_BASED_HLT_EXITING | VMX_PRIMARY_BASED_ACTIVATE_SECONDARY_CONTROLS | VMX_PRIMARY_BASED_USE_MSR_BITMAPS,
			IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
		AdjustVmcsControlField(VMX_SECONDARY_BASED_ENABLE_RDTSCP | VMX_SECONDARY_BASED_ENABLE_XSAVES_XRSTORS | VMX_SECONDARY_BASED_ENABLE_INVPCID,
			IA32_VMX_PROCBASED_CTLS2));
	__vmx_vmwrite(PIN_BASED_VM_EXECUTION_CONTROLS,
		AdjustVmcsControlField(0, IA32_VMX_PINBASED_CTLS));
	__vmx_vmwrite(PRIMARY_VM_EXIT_CONTROLS,
		AdjustVmcsControlField(VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_ACK_INTERRUPT_ON_EXIT, IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS,
		AdjustVmcsControlField(VMX_ENTRY_IA32E_MODE_GUEST, IA32_VMX_ENTRY_CTLS));

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTERRUPTION_INFO_FIELD, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, (1 << 10));
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_FULL, __readmsr(IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_EFER_FULL, __readmsr(IA32_EFER));

	
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_IA32_EFER_FULL, __readmsr(IA32_EFER));

	__vmx_vmwrite(GUEST_GDTR_BASE, GetGDTBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIDTBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGDTLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIDTLimit());
	__vmx_vmwrite(GUEST_RFLAGS, GetRflags());
	
	__vmx_vmwrite(GUEST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

	SEGMENT_DESCRIPTOR segDesc = { 0 };
	if (!(InitSegmentDescriptor(gdtBase, GetTR(), &segDesc)))
	{
		return FALSE;
	}
	__vmx_vmwrite(HOST_TR_BASE, segDesc.baseAddr);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_GS_BASE));
	__vmx_vmwrite(HOST_GDTR_BASE, GetGDTBase());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIDTBase());

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

	__vmx_vmwrite(ADDR_OF_MSR_BITMAPS_FULL, WvsrPaFromVa(systemData->msrBitmap));
	__vmx_vmwrite(GUEST_RIP, gGuestMappedArea);
	__vmx_vmwrite(GUEST_RSP, gGuestMappedArea);

	__vmx_vmwrite(HOST_RSP, (UINT64)(systemData->vmmStack + VMM_STACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (UINT64)VmExitHandler);

	return TRUE;
}

/*
*  On success, returns a pointer to the virtual address of the vmcs region.
*  On error, returns null
*/
UINT64* InitVmcsRegion()
{
	PVMCS_REGION pVmcsRegion = NULL;
	PHYSICAL_ADDRESS maxPhysicalAddress = { 0 };
	IA32_VMX_BASIC_MSR vmxBasicMsr = { 0 };
	vmxBasicMsr.flags = __readmsr(IA32_VMX_BASIC);
	maxPhysicalAddress.QuadPart = MAXULONG64;

	pVmcsRegion = (PVMCS_REGION)MmAllocateContiguousMemory(sizeof(VMCS_REGION), maxPhysicalAddress);
	if (!pVmcsRegion) 
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to allocate vmcs region\n"));
		return NULL;
	}
	RtlZeroMemory(pVmcsRegion, sizeof(VMCS_REGION));
	pVmcsRegion->vmcsRevisionId = (UINT32)vmxBasicMsr.Bitfield.revisionId;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
		"[*] vmcs region initialized, addr: %p, revision: %d\n", pVmcsRegion, pVmcsRegion->vmcsRevisionId));

	return pVmcsRegion;
}

VOID DeallocVmcsRegion(UINT64* vmcsRegion) 
{
	MmFreeContiguousMemory(vmcsRegion);
}

BOOLEAN AllocSystemData(PSYSTEM_DATA systemData) 
{
	systemData->vmxonRegion = InitVmcsRegion();
	if (!(systemData->vmxonRegion))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmxon region init failed\n"));
		return FALSE;
	}

	systemData->vmcsRegion = InitVmcsRegion();
	if (!(systemData->vmcsRegion))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmcs region init failed\n"));
		DeallocVmcsRegion(systemData->vmxonRegion);
		return FALSE;
	}
	
	// The size of the kernel-mode stack is limited to approximately three pages
	systemData->vmmStack = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, WVSR_TAG);
	if (!systemData->vmmStack)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to allocate vmmStack\n"));
		DeallocVmcsRegion(systemData->vmxonRegion);
		DeallocVmcsRegion(systemData->vmcsRegion);
		return FALSE;
	}

	systemData->msrBitmap = ExAllocatePoolZero(NonPagedPool, PAGE_SIZE, WVSR_TAG);
	if (!(systemData->msrBitmap))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to allocate msr bitmap\n"));
		DeallocVmcsRegion(systemData->vmxonRegion);
		DeallocVmcsRegion(systemData->vmcsRegion);
		ExFreePoolWithTag(systemData->vmmStack, WVSR_TAG);
		return FALSE;
	}
	SetupMsrBitmap(systemData->msrBitmap);

	systemData->eptState.eptp = InitEpt();
	if (!(systemData->eptState.eptp))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] ept init failed\n"));
		DeallocVmcsRegion(systemData->vmxonRegion);
		DeallocVmcsRegion(systemData->vmcsRegion);
		ExFreePoolWithTag(systemData->vmmStack, WVSR_TAG);
		ExFreePoolWithTag(systemData->msrBitmap, WVSR_TAG);
		return FALSE;
	}

	BuildMtrrMap(&systemData->eptState);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] SystemData initialized, addr: %p\n", systemData));

	return TRUE;
}

VOID DeallocSystemData(PSYSTEM_DATA systemData)
{
	DeallocVmcsRegion(systemData->vmxonRegion);
	DeallocVmcsRegion(systemData->vmcsRegion);
	ExFreePoolWithTag(systemData->vmmStack, WVSR_TAG);
	ExFreePoolWithTag(systemData->msrBitmap, WVSR_TAG);
}

VOID WvsrVmExitHandler(PREGS guestRegs)
{
	VM_EXIT_DATA exitReason = { 0 };
	UINT64 exitQualification = 0;
	KIRQL savedIrql = KeGetCurrentIrql();

	if (savedIrql < DISPATCH_LEVEL)
	{
		KeRaiseIrqlToDpcLevel();
	}

	__vmx_vmread(EXIT_REASON, &exitReason.flags);
	__vmx_vmread(EXIT_QUALIFICATION, &exitQualification);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
		"[*] exit reason: %d, exit qualification: %d\n", exitReason.Bitfield.reason, exitQualification));

	// Implement exit handlers for the different exit reasons as needed
	switch (exitReason.Bitfield.reason)
	{
	case VM_EXIT_INVEPT:
	case VM_EXIT_INVVPID:
	case VM_EXIT_VMCLEAR:
	case VM_EXIT_VMLAUNCH:
	case VM_EXIT_VMPTRLD:
	case VM_EXIT_VMPTRST:
	case VM_EXIT_VMRESUME:
	case VM_EXIT_VMXOFF:
	case VM_EXIT_VMXON:
	case VM_EXIT_VMREAD:
	case VM_EXIT_VMWRITE:
	{
		VmExitVmxHandler(guestRegs);
		IncrementIp();
		break;
	}
	case VM_EXIT_MSR_READ:
	{
		VmExitMsrReadHandler(guestRegs);
		IncrementIp();
		break;
	}
	case VM_EXIT_MSR_WRITE:
	{
		VmExitMsrWriteHandler(guestRegs);
		IncrementIp();
		break;
	}
	case VM_EXIT_CPUID:
	{
		VmExitCpuidHandler(guestRegs);
		IncrementIp();
		break;
	}
	case VM_EXIT_CR_ACCESS:
	{
		VmExitCrAccessHandler(guestRegs);
		IncrementIp();
		break;
	}
	case VM_EXIT_HLT:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] Hit Halt VM Exit reason!\n"));
		IncrementIp();
		KdBreakPoint();
		break;
	}
	default:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Default Exit!\n"));
		KdBreakPoint();
		break;
	}
	}

	if (savedIrql < DISPATCH_LEVEL)
	{
		KeLowerIrql(savedIrql);
	}
}

NTSTATUS WvsrCheckFeatures()
{
	if (!NT_SUCCESS(CheckVmxSupport()) ||
		!NT_SUCCESS(CheckEptFeatures()))
	{
		return STATUS_NOT_SUPPORTED;
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS WvsrInitVm() 
{
	gSystemData = (PSYSTEM_DATA)ExAllocatePoolWithTag(NonPagedPool, CPU_COUNT * sizeof(SYSTEM_DATA), WVSR_TAG);
	if (gSystemData == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	for (int coreIndex = 0; coreIndex < CPU_COUNT; coreIndex++)
	{
		// Schedule the i-th logic processor
		KeSetSystemAffinityThread(1 << coreIndex);

		// Allocate and init VM resources
		if (!(AllocSystemData(&gSystemData[coreIndex])))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Allocation failed for core %d\n", coreIndex));
			return STATUS_UNSUCCESSFUL;
		}
		if (!(VmxonOp(WvsrPaFromVa((&gSystemData[coreIndex])->vmxonRegion))))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmxon failed for core %d\n", coreIndex));
			return STATUS_UNSUCCESSFUL;
		}
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] core %d running in vmx root\n", coreIndex));
	}

	return STATUS_SUCCESS;
}

VOID WvsrStartVm(UINT32 processorId, NTSTATUS* ntStatus)
{
	UINT64 status = 0;

	KeSetSystemAffinityThread(1 << processorId);

	// Enter "Inactive, Not Current, Clear" state (see Intel SDM Sep.2023 Figure 25-1)
	if (!(VmclearOp(WvsrPaFromVa((&gSystemData[processorId])->vmcsRegion))))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmclear failed for core %d\n", processorId));
		return STATUS_UNSUCCESSFUL;
	}

	// Enter "Active, Current, Clear" state (see Intel SD Sep.2023 Figure 25-1)
	if (!(VmptrldOp(WvsrPaFromVa((&gSystemData[processorId])->vmcsRegion))))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmptrld failed for core %d\n", processorId));
		return STATUS_UNSUCCESSFUL;
	}

	if (!SetupVmcs(&gSystemData[processorId]))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] vmcs setup failed for core %d\n", processorId));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] Launching core %d\n", processorId));
	status = __vmx_vmlaunch();

	__vmx_vmread(VM_INSTRUCTION_ERROR, &status);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Error Launching core %d Error: %llx\n", processorId, status));

	*ntStatus = STATUS_UNSUCCESSFUL;
}

VOID WvsrStopVm()
{
	for (int i = 0; i < CPU_COUNT; i++)
	{
		// Schedule the i-th logic processor
		KeSetSystemAffinityThread(1 << i); 
		VmxoffOp();
		DeallocSystemData(&gSystemData[i]);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[*] Stopping core %d\n", i));
	}
	ExFreePool(gSystemData);
}
