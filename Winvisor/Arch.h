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

typedef struct _RAW_SEGMENT_DESCRIPTOR
{
	UINT16 segLimit0; // bits 0-15
	UINT16 baseAddr0; // bits 16-31
	UINT8 baseAddr1; // bits 32-39
	UINT8 accessByte; // bits 40-47
	UINT8 seglimit1_flags; // limit: bits 48-51, flags: bits 52-55
	UINT8 baseAddr2; // bits 56-63
} RAW_SEGMENT_DESCRIPTOR, * PRAW_SEGMENT_DESCRIPTOR;

typedef union _SEG_DESC_ACCESS_BYTE
{
	struct
	{
		UINT8 A : 1; // Accessed bit
		UINT8 RW : 1; // Readable bit/Writable bit
		UINT8 DC : 1; // Direction bit/Conforming bit
		UINT8 E : 1; // Executable bit
		UINT8 S : 1; // Descriptor type bit
		UINT8 DPL : 2; // Descriptor privilege level field
		UINT8 P : 1; // Present bit
	} Bitfield;
	UINT8 flags;
} SEG_DESC_ACCESS_BYTE, * PSEG_DESC_ACCESS_BYTE;

typedef union _SEG_DESC_FLAGS
{
	struct
	{
		UINT8 reserved : 1;
		UINT8 L : 1; // Long-mode code flag
		UINT8 DB : 1; // Size flag
		UINT8 G : 1; // Granularity flag
	} Bitfield;
	UINT8 flags;
} SEG_DESC_FLAGS, * PSEG_DESC_FLAGS;

typedef struct _SEGMENT_DESCRIPTOR
{
	UINT32 segLimit;
	UINT64 baseAddr;
	SEG_DESC_ACCESS_BYTE accessByte;
	SEG_DESC_FLAGS flags;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;


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
