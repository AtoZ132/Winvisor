#pragma once


// MSR numbers
#define IA32_FEATURE_CONTROL 0x3a
#define IA32_FEATURE_CONTROL_LOCK_BIT 0x1
#define IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX 0x4
#define IA32_VMX_BASIC 0x480


// MSR structures
typedef union _IA32_VMX_BASIC 
{
	struct 
	{
		UINT32 revisionId : 31;
		UINT32 reserved1 : 1;
		UINT32 vmxonRegionSize : 12;
		UINT32 isVmxonRegionSizeFieldZero : 1;
		UINT32 reserved2 : 3;
		UINT32 is64bitPhysicalAddressingWidth: 1;
		UINT32 dualMonitorSMISupport : 1;
		UINT32 vmcsMemoryType : 4;
		UINT32 vmexitReportInfo: 1;
		UINT32 vmxControl1CanClear: 1;
		UINT32 vmentryHWfaultWithErrCode: 1;
		UINT32 reserved3 : 7;
	} Bitfield;
	UINT64 flags;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;
