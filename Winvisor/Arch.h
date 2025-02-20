#pragma once


// MSR addresses
#define IA32_FEATURE_CONTROL 0x3A
#define IA32_FEATURE_CONTROL_LOCK_BIT 0x1
#define IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX 0x4
#define IA32_SYSENTER_CS 0x174
#define IA32_SYSENTER_ESP 0x175
#define IA32_SYSENTER_EIP 0x176
#define IA32_VMX_BASIC 0x480
#define IA32_DEBUGCTL 0x1D9
#define IA32_VMX_PINBASED_CTLS 0x481
#define IA32_VMX_PROCBASED_CTLS 0x482
#define IA32_VMX_EXIT_CTLS 0x483
#define IA32_VMX_ENTRY_CTLS 0x484
#define IA32_VMX_MISC 0x485
#define IA32_VMX_PROCBASED_CTLS2 0x48B
#define IA32_EFER 0xC0000080
#define IA32_FS_BASE 0xC0000100
#define IA32_GS_BASE 0xC0000101


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

typedef struct _RAW_SEGMENT_DESCRIPTOR
{
	UINT16 segLimit0; // bits 0-15
	UINT16 baseAddr0; // bits 16-31
	UINT8 baseAddr1; // bits 32-39
	UINT8 accessByte; // bits 40-47
	UINT8 seglimit1_flags; // limit: bits 48-51, flags: bits 52-55
	UINT8 baseAddr2; // bits 56-63
} RAW_SEGMENT_DESCRIPTOR, * PRAW_SEGMENT_DESCRIPTOR;

typedef union _SEG_DESC_ACCESS_RIGHT
{
	struct
	{
		UINT16 TYPE : 4;
		UINT16 S : 1;   
		UINT16 DPL : 2; 
		UINT16 P : 1;   
		UINT16 AVL : 1; 
		UINT16 L : 1;   
		UINT16 DB : 1;  
		UINT16 G : 1;   
		UINT16 GAP : 4;
	} Bitfield;
	UINT16 flags;
} SEG_DESC_ACCESS_RIGHT, * PSEG_DESC_ACCESS_RIGHT;

typedef struct _SEGMENT_DESCRIPTOR
{
	UINT32 segLimit;
	UINT64 baseAddr;
	SEG_DESC_ACCESS_RIGHT accessRight;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef union _MSR
{
	struct
	{
		UINT32 low;
		UINT32 high;
	} Fields;

	UINT64 flags;
} MSR, * PMSR;

typedef struct _REGS
{
	UINT64 rax;
	UINT64 rcx;
	UINT64 rdx;
	UINT64 rbx;
	UINT64 rsp;
	UINT64 rbp;
	UINT64 rsi;
	UINT64 rdi;
	UINT64 r8;
	UINT64 r9;
	UINT64 r10;
	UINT64 r11;
	UINT64 r12;
	UINT64 r13;
	UINT64 r14;
	UINT64 r15;
} REGS, *PREGS;


enum SegmentSelector
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};
