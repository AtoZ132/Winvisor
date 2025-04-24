#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "Arch.h"
#include "WinvisorUtil.h"
#include "Ept.h"


#define VMM_STACK_SIZE (3 * PAGE_SIZE)

// Definitions of Primary Processor-Based VM-Execution Controls
#define PIN_BASED_EXTERNAL_INTERRUPT_EXITING    (1U << 0)
#define PIN_BASED_NMI_EXITING                   (1U << 3)
#define PIN_BASED_VIRTUAL_NMIS                  (1U << 5)
#define PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER (1U << 6)
#define PIN_BASED_PROCESS_POSTED_INTERRUPTS     (1U << 7)

// Definitions of Primary Processor-Based VM-Execution Controls
#define VMX_PRIMARY_BASED_INTERRUPT_WINDOW_EXITING    (1U << 2)
#define VMX_PRIMARY_BASED_USE_TSC_OFFSETTING          (1U << 3)
#define VMX_PRIMARY_BASED_HLT_EXITING                 (1U << 7)
#define VMX_PRIMARY_BASED_INVLPG_EXITING              (1U << 9)
#define VMX_PRIMARY_BASED_MWAIT_EXITING               (1U << 10) 
#define VMX_PRIMARY_BASED_RDPMC_EXITING               (1U << 11) 
#define VMX_PRIMARY_BASED_RDTSC_EXITING               (1U << 12) 
#define VMX_PRIMARY_BASED_CR3_LOAD_EXITING            (1U << 15)
#define VMX_PRIMARY_BASED_CR3_STORE_EXITING           (1U << 16)
#define VMX_PRIMARY_BASED_ACTIVATE_TERTIARY_CONTROLS  (1U << 17)
#define VMX_PRIMARY_BASED_CR8_LOAD_EXITING            (1U << 19)
#define VMX_PRIMARY_BASED_CR8_STORE_EXITING           (1U << 20) 
#define VMX_PRIMARY_BASED_USE_TPR_SHADOW              (1U << 21)
#define VMX_PRIMARY_BASED_NMI_WINDOW_EXITING          (1U << 22)
#define VMX_PRIMARY_BASED_MOV_DR_EXITING              (1U << 23)
#define VMX_PRIMARY_BASED_UNCONDITIONAL_IO_EXITING    (1U << 24)
#define VMX_PRIMARY_BASED_USE_IO_BITMAPS              (1U << 25)
#define VMX_PRIMARY_BASED_MONITOR_TRAP_FLAG           (1U << 27)
#define VMX_PRIMARY_BASED_USE_MSR_BITMAPS             (1U << 28)
#define VMX_PRIMARY_BASED_MONITOR_EXITING             (1U << 29)
#define VMX_PRIMARY_BASED_PAUSE_EXITING               (1U << 30)
#define VMX_PRIMARY_BASED_ACTIVATE_SECONDARY_CONTROLS (1U << 31)

// Definitions of Secondary Processor-Based VM-Execution Controls
#define VMX_SECONDARY_BASED_VIRTUALIZE_APIC_ACCESSES               (1U << 0)
#define VMX_SECONDARY_BASED_ENABLE_EPT                             (1U << 1) 
#define VMX_SECONDARY_BASED_DESCRIPTOR_TABLE_EXITING               (1U << 2)
#define VMX_SECONDARY_BASED_ENABLE_RDTSCP                          (1U << 3)
#define VMX_SECONDARY_BASED_VIRTUALIZE_X2APIC_MODE                 (1U << 4)
#define VMX_SECONDARY_BASED_ENABLE_VPID                            (1U << 5)
#define VMX_SECONDARY_BASED_WBINVD_EXITING                         (1U << 6)
#define VMX_SECONDARY_BASED_UNRESTRICTED_GUEST                     (1U << 7)
#define VMX_SECONDARY_BASED_APIC_REGISTER_VIRTUALIZATION           (1U << 8)
#define VMX_SECONDARY_BASED_VIRTUAL_INTERRUPT_DELIVERY             (1U << 9)
#define VMX_SECONDARY_BASED_PAUSE_LOOP_EXITING                     (1U << 10)
#define VMX_SECONDARY_BASED_RDRAND_EXITING                         (1U << 11)
#define VMX_SECONDARY_BASED_ENABLE_INVPCID                         (1U << 12)
#define VMX_SECONDARY_BASED_ENABLE_VM_FUNCTIONS                    (1U << 13)
#define VMX_SECONDARY_BASED_VMCS_SHADOWING                         (1U << 14)
#define VMX_SECONDARY_BASED_ENABLE_ENCLS_EXITING                   (1U << 15)
#define VMX_SECONDARY_BASED_RDSEED_EXITING                         (1U << 16)
#define VMX_SECONDARY_BASED_ENABLE_PML                             (1U << 17)
#define VMX_SECONDARY_BASED_EPT_VIOLATION_VE                       (1U << 18)
#define VMX_SECONDARY_BASED_CONCEAL_VMX_FROM_PT                    (1U << 19)
#define VMX_SECONDARY_BASED_ENABLE_XSAVES_XRSTORS                  (1U << 20)
#define VMX_SECONDARY_BASED_PASID_TRANSLATION                      (1U << 21)
#define VMX_SECONDARY_BASED_MODE_BASED_EXECUTE_CONTROL_FOR_EPT     (1U << 22)
#define VMX_SECONDARY_BASED_SUB_PAGE_WRITE_PREMISSIONS_FOR_EPT     (1U << 23)
#define VMX_SECONDARY_BASED_INTEL_PT_USES_GUEST_PHYSICAL_ADDRESSES (1U << 24)
#define VMX_SECONDARY_BASED_USE_TSC_SCALING                        (1U << 25)
#define VMX_SECONDARY_BASED_ENABLE_USER_WAIT_AND_PAUSE             (1U << 26)
#define VMX_SECONDARY_BASED_ENABLE_PCONFIG                         (1U << 27)
#define VMX_SECONDARY_BASED_ENABLE_ENCLV_EXITING                   (1U << 28)
#define VMX_SECONDARY_BASED_VMM_BUS_LOCK_DETECTION                 (1U << 30)
#define VMX_SECONDARY_BASED_INSTRUCTION_TIMEOUT                    (1U << 31)

// Definitions of Primary VM-Exit Controls
#define VM_EXIT_SAVE_DEBUG_CONTROLS       (1U << 2)
#define VM_EXIT_HOST_ADDR_SPACE_SIZE      (1U << 9)
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL     (1U << 12)
#define VM_EXIT_ACK_INTERRUPT_ON_EXIT     (1U << 15)
#define VM_EXIT_SAVE_IA32_PAT             (1U << 18) 
#define VM_EXIT_LOAD_IA32_PAT             (1U << 19)
#define VM_EXIT_SAVE_IA32_EFER            (1U << 20) 
#define VM_EXIT_LOAD_IA32_EFER            (1U << 21)
#define VM_EXIT_SAVE_PREEMPTION_TIMER     (1U << 22)
#define VM_EXIT_CLEAR_IA32_BNDCFGS        (1U << 23)
#define VM_EXIT_CONCEAL_VMX_FROM_PT       (1U << 24)
#define VM_EXIT_CLEAR_IA32_RTIT_CTL       (1U << 25)
#define VM_EXIT_CLEAR_IA32_LBR_CTL        (1U << 26)
#define VM_EXIT_CLEAR_UINV                (1U << 27) 
#define VM_EXIT_LOAD_CET_STATE            (1U << 28)
#define VM_EXIT_LOAD_PKRS                 (1U << 29)
#define VM_EXIT_SAVE_PERF_GLOBAL_CTRL     (1U << 30)
#define VM_EXIT_ACTIVATE_SECONDARY_CTRL   (1U << 31)

// Definitions of VM-Entry Controls
#define VMX_ENTRY_LOAD_DEBUG_CONTROLS               (1 << 2)
#define VMX_ENTRY_IA32E_MODE_GUEST                  (1 << 9)
#define VMX_ENTRY_TO_SMM                            (1 << 10)
#define VMX_ENTRY_DEACTIVATE_DUAL_MONITOR_TREATMENT (1 << 11)
#define VMX_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL        (1 << 13)
#define VMX_ENTRY_LOAD_IA32_PAT                     (1 << 14)
#define VMX_ENTRY_LOAD_IA32_EFER                    (1 << 15)
#define VMX_ENTRY_LOAD_IA32_BNDCFGS                 (1 << 16)
#define VMX_ENTRY_CONCEAL_VMX_FROM_PT               (1 << 17)
#define VMX_ENTRY_LOAD_IA32_RTIT_CTL                (1 << 18)
#define VMX_ENTRY_LOAD_UINV                         (1 << 19)
#define VMX_ENTRY_LOAD_CET_STATE                    (1 << 20)
#define VMX_ENTRY_LOAD_GUEST_IA32_LBR_CTL           (1 << 21)
#define VMX_ENTRY_LOAD_PKRS                         (1 << 22)

// CR access vm-exit qualification defines
#define MOV_TO_CR			0
#define MOV_FROM_CR			1
#define CTLS				2
#define LMSW				3
#define LMSW_REG_OPERAND	0
#define LMSW_MEMORY_OPERAND 1
#define MOV_CR_RAX			0
#define MOV_CR_RCX			1
#define MOV_CR_RDX			2
#define MOV_CR_RBX			3
#define MOV_CR_RSP			4
#define MOV_CR_RBP			5
#define MOV_CR_RSI			6
#define MOV_CR_RDI			7
#define MOV_CR_R8			8
#define MOV_CR_R9			9
#define MOV_CR_R10			10
#define MOV_CR_R11			11
#define MOV_CR_R12			12
#define MOV_CR_R13			13
#define MOV_CR_R14			14
#define MOV_CR_R15			15


/*
* vmcs_revision_id - 
*	Bits 30:0: VMCS revision identifier
*	Bit 31: shadow-VMCS indicator
*/
#pragma pack(push, 1)
typedef struct _VMCS_REGION
{
	UINT32 vmcsRevisionId;
	UINT32 vmxAbortIndicator;
	UINT8  vmcsData[PAGE_SIZE - 8];
} VMCS_REGION, *PVMCS_REGION;
#pragma pack(pop)

typedef struct _SYSTEM_DATA SYSTEM_DATA, * PSYSTEM_DATA;
/*
* Keep the systemData pointer on top of the host stack for availability during vm-exits
*/
typedef struct _VMM_STACK 
{
	UINT8 vmmStack[VMM_STACK_SIZE];
} VMM_STACK, * PVMM_STACK;

/*
* the VMCS regions hold the virtual address to the regions
*/
typedef struct _SYSTEM_DATA 
{
	PVMCS_REGION vmxonRegion;
	PVMCS_REGION vmcsRegion;
	VMM_STACK vmmStack;
	UINT64 msrBitmap;
	EPT_STATE eptState;
} SYSTEM_DATA, *PSYSTEM_DATA;

typedef union _VMCS_COMP_ENCODING 
{
	struct 
	{
		UINT32 accessType : 1; 
		UINT32 index : 9;
		UINT32 type : 2;
		UINT32 reserved : 1;
		UINT32 width : 2;
		UINT32 reserved2 : 17;
	} Bitfield;
	UINT32 flags;
} VMCS_COMP_ENCODING, *PVMCS_COMP_ENCODING;

typedef union _VM_EXIT_DATA
{
	struct
	{
		UINT16 reason;
		UINT32 reserved : 9;
		UINT32 premBusyShadowStack : 1;
		UINT32 vmmBusyLock : 1;
		UINT32 enclaveMode : 1;
		UINT32 reserved2 : 4;
	} Bitfield;
	UINT32 flags;
} VM_EXIT_DATA, *PVM_EXIT_DATA;

typedef union _MOV_CR_ACCESS_QUAL
{
	struct
	{
		UINT8 crNumber : 4;
		UINT8 accessType : 2;
		UINT8 lmswOpType : 1;
		UINT8 unused : 1;
		UINT8 gpReg : 4;
		UINT8 unused2 : 4;
		UINT16 sourceData : 16; // For LMSW, the LMSW source data. For CLTS and MOV CR, cleared to 0
		UINT32 unused3 : 32; // These bits exist only on processors that support Intel 64 architecture.
	}Bitfield;
	UINT64 flags;
} MOV_CR_ACCESS_QUAL, *PMOV_CR_ACCESS_QUAL;


/*
* (0 = full; 1 = high); must be full for 16-bit, 32-bit, and natural-width fields
*/
enum VmcsAccessType
{
	FULL = 0,
	HIGH = 1
};

/*
* Type:
*	0: control
*	1: VM-exit information
*	2: guest state
*	3: host state
*/
enum VmcsFieldType
{
	CONTROL = 0,
	VM_EXIT_INFO = 1,
	GUEST_STATE = 2,
	HOST_STATE = 3
};

/*
* Width:
*	0: 16-bit
*	1: 64-bit
*	2: 32-bit
*	3: natural-width
*/
enum VmcsFieldWidth
{
	BITS_16 = 0,
	BITS_64 = 1,
	BITS_32 = 2,
	NATURAL_WIDTH = 3
};

/*
*	As of September 2023 manual version
*/
enum VmcsFields
{
	// 16-Bit Control Fields
	VIRTUAL_PROCESSOR_IDENTIFIER					= 0x00000000,
	POSTED_INTERRUPT_NOTIFICATION_VECTOR			= 0x00000002,
	EPTP_INDEX										= 0x00000004,
	HLAT_PREFIX_SIZE								= 0x00000006,
	LAST_PID_POINTER_INDEX							= 0x00000008,
													
	// 16-Bit Guest-State Fields					
	GUEST_ES_SELECTOR								= 0x00000800,
	GUEST_CS_SELECTOR								= 0x00000802,
	GUEST_SS_SELECTOR								= 0x00000804,
	GUEST_DS_SELECTOR								= 0x00000806,
	GUEST_FS_SELECTOR								= 0x00000808,
	GUEST_GS_SELECTOR								= 0x0000080A,
	GUEST_LDTR_SELECTOR								= 0x0000080C,
	GUEST_TR_SELECTOR								= 0x0000080E,
	GUEST_INTERRUPT_STATUS							= 0x00000810,
	PML_INDEX										= 0x00000812,
	GUEST_UINV										= 0x00000814,
													
	// 16-Bit Host-State Fields						
	HOST_ES_SELECTOR								= 0x00000C00,
	HOST_CS_SELECTOR								= 0x00000C02,
	HOST_SS_SELECTOR								= 0x00000C04,
	HOST_DS_SELECTOR								= 0x00000C06,
	HOST_FS_SELECTOR								= 0x00000C08,
	HOST_GS_SELECTOR								= 0x00000C0A,
	HOST_TR_SELECTOR								= 0x00000C0C,
													
	// 64-Bit Control Fields						
	ADDR_OF_IO_BITMAP_A_FULL						= 0x00002000,
	ADDR_OF_IO_BITMAP_A_HIGH						= 0x00002001,
	ADDR_OF_IO_BITMAP_B_FULL						= 0x00002002,
	ADDR_OF_IO_BITMAP_B_HIGH						= 0x00002003,
	ADDR_OF_MSR_BITMAPS_FULL						= 0x00002004,
	ADDR_OF_MSR_BITMAPS_HIGH						= 0x00002005,
	VMEXIT_MSR_STORE_ADDR_FULL						= 0x00002006,
	VMEXIT_MSR_STORE_ADDR_HIGH						= 0x00002007,
	VMEXIT_MSR_LOAD_ADDR_FULL						= 0x00002008,
	VMEXIT_MSR_LOAD_ADDR_HIGH						= 0x00002009,
	VMENTRY_MSR_LOAD_ADDR_FULL						= 0x0000200A,
	VMENTRY_MSR_LOAD_ADDR_HIGH						= 0x0000200B,
	EXECUTIVE_VMCS_POINTER_FULL						= 0x0000200C,
	EXECUTIVE_VMCS_POINTER_HIGH						= 0x0000200D,
	PML_ADDR_FULL									= 0x0000200E,
	PML_ADDR_HIGH			 						= 0x0000200F,
	TSC_OFFSET_FULL				 					= 0x00002010,
	TSC_OFFSET_HIGH									= 0x00002011,
	VIRTUAL_APIC_ADDR_FULL							= 0x00002012,
	VIRTUAL_APIC_ADDR_HIGH							= 0x00002013,
	APIC_ACCESS_ADDR_FULL							= 0x00002014,
	APIC_ACCESS_ADDR_HIGH							= 0x00002015,
	POSTED_INTERRUPT_DESCRIPTOR_ADDR_FULL			= 0x00002016,
	POSTED_INTERRUPT_DESCRIPTOR_ADDR_HIGH			= 0x00002017,
	VM_FUNCTION_CONTROLS_FULL						= 0x00002018,
	VM_FUNCTION_CONTROLS_HIGH						= 0x00002019,
	EPT_POINTER_FULL								= 0x0000201A,
	EPT_POINTER_HIGH								= 0x0000201B,
	EOI_EXIT_BITMAP0_FULL							= 0x0000201C,
	EOI_EXIT_BITMAP0_HIGH							= 0x0000201D,
	EOI_EXIT_BITMAP1_FULL							= 0x0000201E,
	EOI_EXIT_BITMAP1_HIGH							= 0x0000201F,
	EOI_EXIT_BITMAP2_FULL							= 0x00002020,
	EOI_EXIT_BITMAP2_HIGH							= 0x00002021,
	EOI_EXIT_BITMAP3_FULL							= 0x00002022,
	EOI_EXIT_BITMAP3_HIGH							= 0x00002023,
	EPTP_LIST_ADDRESS_FULL			  				= 0x00002024,
	EPTP_LIST_ADDRESS_HIGH			  				= 0x00002025,
	VMREAD_BITMAP_ADDR_FULL			  				= 0x00002026,
	VMREAD_BITMAP_ADDR_HIGH							= 0x00002027,
	VMWRITE_BITMAP_ADDR_FULL						= 0x00002028,
	VMWRITE_BITMAP_ADDR_HIGH						= 0x00002029,
	VIRTUAL_EXCEPTION_INFO_ADDR_FULL				= 0x0000202a,
	VIRTUAL_EXCEPTION_INFO_ADDR_HIGH				= 0x0000202b,
	XSS_EXITING_BITMAP_FULL							= 0x0000202c,
	XSS_EXITING_BITMAP_HIGH							= 0x0000202d,
	ENCLS_EXITING_BITMAP_FULL						= 0x0000202e,
	ENCLS_EXITING_BITMAP_HIGH						= 0x0000202f,
	SUB_PAGE_PERMISSION_TABLE_POINTER_FULL			= 0x00002030,
	SUB_PAGE_PERMISSION_TABLE_POINTER_HIGH			= 0x00002031,
	TSC_MULTIPLIER_FULL								= 0x00002032,
	TSC_MULTIPLIER_HIGH								= 0x00002033,
	TERTIARY_PROC_EXECUTION_CONTROLS_FULL			= 0x00002034,
	TERTIARY_PROC_EXECUTION_CONTROLS_HIGH			= 0x00002035,
	ENCLV_EXITING_BITMAP_FULL						= 0x00002036,
	ENCLV_EXITING_BITMAP_HIGH						= 0x00002037,
	LOW_PASID_DIRECTORY_ADDR_FULL					= 0x00002038,
	LOW_PASID_DIRECTORY_ADDR_HIGH					= 0x00002039,
	HIGH_PASID_DIRECTORY_ADDR_FULL					= 0x0000203a,
	HIGH_PASID_DIRECTORY_ADDR_HIGH					= 0x0000203b,
	SHARED_EPT_POINTER_FULL							= 0x0000203c,
	SHARED_EPT_POINTER_HIGH							= 0x0000203d,
	PCONFIG_EXITING_BITMAP_FULL						= 0x0000203e,
	PCONFIG_EXITING_BITMAP_HIGH						= 0x0000203f,
	HLATP_FULL										= 0x00002040,
	HLATP_HIGH										= 0x00002041,
	PID_POINTER_TABLE_ADDR_FULL						= 0x00002042,
	PID_POINTER_TABLE_ADDR_HIGH						= 0x00002043,
	SECONDARY_VMEXIT_CONTROLS_FULL					= 0x00002044,
	SECONDARY_VMEXIT_CONTROLS_HIGH					= 0x00002045,
	IA32_SPEC_CTRL_MASK_FULL						= 0x0000204a,
	IA32_SPEC_CTRL_MASK_HIGH						= 0x0000204b,
	IA32_SPEC_CTRL_SHADOW_FULL						= 0x0000204c,
	IA32_SPEC_CTRL_SHADOW_HIGH						= 0x0000204d,
													
	// 64-Bit Read-Only Data Field					
	GUEST_PHYSICAL_ADDR_FULL						= 0x00002400,
	GUEST_PHYSICAL_ADDR_HIGH						= 0x00002401,
													
	// 64-Bit Guest-State Fields 					
	VMCS_LINK_POINTER_FULL							= 0x00002800,
	VMCS_LINK_POINTER_HIGH							= 0x00002801,
	GUEST_IA32_DEBUGCTL_FULL						= 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH						= 0x00002803,
	GUEST_IA32_PAT_FULL								= 0x00002804,
	GUEST_IA32_PAT_HIGH								= 0x00002805,
	GUEST_IA32_EFER_FULL							= 0x00002806,
	GUEST_IA32_EFER_HIGH							= 0x00002807,
	GUEST_IA32_PERF_GLOBAL_CTRL_FULL				= 0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_HIGH				= 0x00002809,
	GUEST_PDPTE0_FULL								= 0x0000280a,
	GUEST_PDPTE0_HIGH								= 0x0000280b,
	GUEST_PDPTE1_FULL								= 0x0000280c,
	GUEST_PDPTE1_HIGH								= 0x0000280d,
	GUEST_PDPTE2_FULL								= 0x0000280e,
	GUEST_PDPTE2_HIGH								= 0x0000280f,
	GUEST_PDPTE3_FULL								= 0x00002810,
	GUEST_PDPTE3_HIGH								= 0x00002811,
	GUEST_IA32_BNDCFGS_FULL							= 0x00002812,
	GUEST_IA32_BNDCFGS_HIGH							= 0x00002813,
	GUEST_IA32_RTIT_CTL_FULL						= 0x00002814,
	GUEST_IA32_RTIT_CTL_HIGH						= 0x00002815,
	GUEST_IA32_LBR_CTL_FULL							= 0x00002816,
	GUEST_IA32_LBR_CTL_HIGH							= 0x00002817,
	GUEST_IA32_PKRS_FULL							= 0x00002818,
	GUEST_IA32_PKRS_HIGH							= 0x00002819,
													
	// 64-Bit Host-State Fields						
	HOST_IA32_PAT_FULL								= 0x00002c00,
	HOST_IA32_PAT_HIGH								= 0x00002c01,
	HOST_IA32_EFER_FULL								= 0x00002c02,
	HOST_IA32_EFER_HIGH								= 0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL_FULL					= 0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_HIGH					= 0x00002c05,
	HOST_IA32_PKRS_FULL								= 0x00002c06,
	HOST_IA32_PKRS_HIGH								= 0x00002c07,

	// 32-Bit Control Fields
	PIN_BASED_VM_EXECUTION_CONTROLS					= 0x00004000,
	PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS	= 0x00004002,
	EXCEPTION_BITMAP								= 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK						= 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH						= 0x00004008,
	CR3_TARGET_COUNT								= 0x0000400a,
	PRIMARY_VM_EXIT_CONTROLS						= 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT							= 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT							= 0x00004010,
	VM_ENTRY_CONTROLS								= 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT							= 0x00004014,
	VM_ENTRY_INTERRUPTION_INFO_FIELD				= 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE					= 0x00004018,
	VM_ENTRY_INSTRUCTION_LENGTH						= 0x0000401a,
	TPR_THRESHOLD									= 0x0000401c,
	SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x0000401e,
	PLE_GAP											= 0x00004020,
	PLE_WINDOW										= 0x00004022,
	INSTRUCTION_TIMEOUT_CONTROL						= 0x00004024,
	
	// 32-Bit Read-Only Data Fields
	VM_INSTRUCTION_ERROR							= 0x00004400,
	EXIT_REASON										= 0x00004402,
	VM_EXIT_INTERRUPTION_INFO						= 0x00004404,
	VM_EXIT_INTERRUPTION_ERROR_CODE					= 0x00004406,
	IDT_VECTORING_INFO_FIELD						= 0x00004408,
	IDT_VECTORING_ERROR_CODE						= 0x0000440a,
	VM_EXIT_INSTRUCTION_LENGTH						= 0x0000440c,
	VM_EXIT_INSTRUCTION_INFO						= 0x0000440e,

	// 32-Bit Guest-State Fields
	GUEST_ES_LIMIT									= 0x00004800,
	GUEST_CS_LIMIT									= 0x00004802,
	GUEST_SS_LIMIT									= 0x00004804,
	GUEST_DS_LIMIT									= 0x00004806,
	GUEST_FS_LIMIT									= 0x00004808,
	GUEST_GS_LIMIT									= 0x0000480a,
	GUEST_LDTR_LIMIT								= 0x0000480c,
	GUEST_TR_LIMIT									= 0x0000480e,
	GUEST_GDTR_LIMIT								= 0x00004810,
	GUEST_IDTR_LIMIT								= 0x00004812,
	GUEST_ES_ACCESS_RIGHTS							= 0x00004814,
	GUEST_CS_ACCESS_RIGHTS							= 0x00004816,
	GUEST_SS_ACCESS_RIGHTS							= 0x00004818,
	GUEST_DS_ACCESS_RIGHTS							= 0x0000481a,
	GUEST_FS_ACCESS_RIGHTS							= 0x0000481c,
	GUEST_GS_ACCESS_RIGHTS							= 0x0000481e,
	GUEST_LDTR_ACCESS_RIGHTS						= 0x00004820,
	GUEST_TR_ACCESS_RIGHTS							= 0x00004822,
	GUEST_INTERRUPTIBILITY_STATE					= 0x00004824,
	GUEST_ACTIVITY_STATE							= 0x00004826,
	GUEST_SMBASE									= 0x00004828,
	GUEST_IA32_SYSENTER_CS							= 0x0000482a,
	VMX_PREEMPTION_TIMER_VALUE						= 0x0000482e,

	// 32-Bit Host-State Field
	HOST_IA32_SYSENTER_CS							= 0x00004c00,

	// Natural-Width Control Fields
	CR0_GUEST_HOST_MASK								= 0x00006000,
	CR4_GUEST_HOST_MASK								= 0x00006002,
	CR0_READ_SHADOW									= 0x00006004,
	CR4_READ_SHADOW									= 0x00006006,
	CR3_TARGET_VALUE_0								= 0x00006008,
	CR3_TARGET_VALUE_1								= 0x0000600a,
	CR3_TARGET_VALUE_2								= 0x0000600c,
	CR3_TARGET_VALUE_3								= 0x0000600e,

	// Natural-Width Read-Only Data Fields
	EXIT_QUALIFICATION								= 0x00006400,
	IO_RCX											= 0x00006402,
	IO_RSI											= 0x00006404,
	IO_RDI											= 0x00006406,
	IO_RIP											= 0x00006408,
	GUEST_LINEAR_ADDR								= 0x0000640a,

	// Natural-Width Guest-State Fields
	GUEST_CR0										= 0x00006800,
	GUEST_CR3										= 0x00006802,
	GUEST_CR4										= 0x00006804,
	GUEST_ES_BASE									= 0x00006806,
	GUEST_CS_BASE									= 0x00006808,
	GUEST_SS_BASE									= 0x0000680a,
	GUEST_DS_BASE									= 0x0000680c,
	GUEST_FS_BASE									= 0x0000680e,
	GUEST_GS_BASE									= 0x00006810,
	GUEST_LDTR_BASE									= 0x00006812,
	GUEST_TR_BASE									= 0x00006814,
	GUEST_GDTR_BASE									= 0x00006816,
	GUEST_IDTR_BASE									= 0x00006818,
	GUEST_DR7										= 0x0000681a,
	GUEST_RSP										= 0x0000681c,
	GUEST_RIP										= 0x0000681e,
	GUEST_RFLAGS									= 0x00006820,
	GUEST_PENDING_DEBUG_EXCEPTIONS					= 0x00006822,
	GUEST_IA32_SYSENTER_ESP							= 0x00006824,
	GUEST_IA32_SYSENTER_EIP							= 0x00006826,
	GUEST_IA32_S_CET								= 0x00006828,
	GUEST_SSP										= 0x0000682a,
	GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR				= 0x0000682c,

	// Natural-Width Host-State Fields
	HOST_CR0										= 0x00006c00,
	HOST_CR3										= 0x00006c02,
	HOST_CR4										= 0x00006c04,
	HOST_FS_BASE									= 0x00006c06,
	HOST_GS_BASE									= 0x00006c08,
	HOST_TR_BASE									= 0x00006c0a,
	HOST_GDTR_BASE									= 0x00006c0c,
	HOST_IDTR_BASE									= 0x00006c0e,
	HOST_IA32_SYSENTER_ESP							= 0x00006c10,
	HOST_IA32_SYSENTER_EIP							= 0x00006c12,
	HOST_RSP										= 0x00006c14,
	HOST_RIP										= 0x00006c16,
	HOST_IA32_S_CET									= 0x00006c18,
	HOST_SSP										= 0x00006c1a,
	HOST_IA32_INTERRUPT_SSP_TABLE_ADDR				= 0x00006c1c
};

// Invept types
typedef enum INVEPT_TYPE
{
	SINGLE_CONTEXT = 1,
	GLOBAL_CONTEXT = 2
};

// Table C-1. Basic Exit Reasons
typedef enum VM_EXIT_REASON
{
	VM_EXIT_EXCEPTION_OR_NMI				  = 0,
	VM_EXIT_EXTERNAL_INTERRUPT				  = 1,
	VM_EXIT_TRIPLE_FAULT					  = 2,
	VM_EXIT_INIT_SIGNAL						  = 3,
	VM_EXIT_SIPI							  = 4,
	VM_EXIT_IO_SMI							  = 5,
	VM_EXIT_OTHER_SMI						  = 6,
	VM_EXIT_INTERRUPT_WINDOW				  = 7,
	VM_EXIT_NMI_WINDOW						  = 8,
	VM_EXIT_TASK_SWITCH						  = 9,
	VM_EXIT_CPUID							  = 10,
	VM_EXIT_GETSEC							  = 11,
	VM_EXIT_HLT								  = 12,
	VM_EXIT_INVD							  = 13,
	VM_EXIT_INVLPG							  = 14,
	VM_EXIT_RDPMC							  = 15,
	VM_EXIT_RDTSC							  = 16,
	VM_EXIT_RSM								  = 17,
	VM_EXIT_VMCALL							  = 18,
	VM_EXIT_VMCLEAR							  = 19,
	VM_EXIT_VMLAUNCH						  = 20,
	VM_EXIT_VMPTRLD							  = 21,
	VM_EXIT_VMPTRST							  = 22,
	VM_EXIT_VMREAD							  = 23,
	VM_EXIT_VMRESUME						  = 24,
	VM_EXIT_VMWRITE							  = 25,
	VM_EXIT_VMXOFF							  = 26,
	VM_EXIT_VMXON							  = 27,
	VM_EXIT_CR_ACCESS						  = 28,
	VM_EXIT_DR_ACCESS						  = 29,
	VM_EXIT_IO_INSTRUCTION					  = 30,
	VM_EXIT_MSR_READ						  = 31,
	VM_EXIT_MSR_WRITE						  = 32,
	VM_EXIT_VM_ENTRY_FAIL_INVALID_GUEST_STATE = 33,
	VM_EXIT_VM_ENTRY_FAIL_MSR_LOADING		  = 34,
	VM_EXIT_MWAIT							  = 36,
	VM_EXIT_MONITOR_TRAP_FLAG				  = 37,
	VM_EXIT_MONITOR							  = 39,
	VM_EXIT_PAUSE							  = 40,
	VM_EXIT_VM_ENTRY_FAIL_MACHINE_CHECK		  = 41,
	VM_EXIT_TPR_BELOW_THRESHOLD				  = 43,
	VM_EXIT_APIC_ACCESS						  = 44,
	VM_EXIT_VIRTUALIZED_EOI					  = 45,
	VM_EXIT_GDTR_IDTR_ACCESS				  = 46,
	VM_EXIT_LDTR_TR_ACCESS					  = 47,
	VM_EXIT_EPT_VIOLATION					  = 48,
	VM_EXIT_EPT_MISCONFIGURATION			  = 49,
	VM_EXIT_INVEPT							  = 50,
	VM_EXIT_RDTSCP							  = 51,
	VM_EXIT_VMX_TIMER_EXPIRED				  = 52,
	VM_EXIT_INVVPID							  = 53,
	VM_EXIT_WBINVD_WBNOINVD					  = 54,
	VM_EXIT_XSETBV							  = 55,
	VM_EXIT_APIC_WRITE						  = 56,
	VM_EXIT_RDRAND							  = 57,
	VM_EXIT_INVPCID							  = 58,
	VM_EXIT_VMFUNC							  = 59,
	VM_EXIT_ENCLS							  = 60,
	VM_EXIT_RDSEED							  = 61,
	VM_EXIT_PML_FULL						  = 62,
	VM_EXIT_XSAVES							  = 63,
	VM_EXIT_XRSTORS							  = 64,
	VM_EXIT_PCONFIG							  = 65,
	VM_EXIT_SPP_RELATED_EVENT				  = 66,
	VM_EXIT_UMWAIT							  = 67,
	VM_EXIT_TPAUSE							  = 68,
	VM_EXIT_LOADIWKEY						  = 69,
	VM_EXIT_ENCLV							  = 70,
	VM_EXIT_ENQCMD_PASID_TRANSLATION_FAILURE  = 72,
	VM_EXIT_ENQCMDS_PASID_TRANSLATION_FAILURE = 73,
	VM_EXIT_BUS_LOCK						  = 74,
	VM_EXIT_INSTRUCTION_TIMEOUT				  = 75,
	VM_EXIT_SEAMCALL						  = 76,
	VM_EXIT_TDCALL							  = 77
};


extern void inline InveptOp(int inveptType, PVOID inveptDesc);
extern UINT64 inline GetGDTBase();
extern UINT16 inline GetGDTLimit();
extern UINT64 inline GetIDTBase();
extern UINT16 inline GetIDTLimit();
extern UINT16 inline GetTR();
extern UINT16 inline GetCS();
extern UINT16 inline GetDS();
extern UINT16 inline GetSS();
extern UINT16 inline GetES();
extern UINT16 inline GetFS();
extern UINT16 inline GetGS();
extern UINT64 inline GetRflags();
extern UINT64 inline GetLDTR();
extern void VmExitHandler();
extern void inline InvokeVmcall(UINT64 vmcallNumber, UINT64 param1, UINT64 param2);
extern void VmxSaveState();
extern void VmxRestoreState();

NTSTATUS CheckVmxSupport();
BOOLEAN VmxonOp(UINT64* vmxonRegionPhysical);
BOOLEAN VmptrldOp(UINT64* vmcsPhysical);
BOOLEAN VmclearOp(UINT64* vmcsPhysicalAddress);
VOID VmxoffOp();
VOID VmxInveptOp(UINT64 context);
VOID VmResumeErrorHandler();
VOID IncrementIp();
VOID VmExitCpuidHandler(PREGS regs);
VOID VmExitCrAccessHandler(PREGS regs);
VOID VmExitMsrReadHandler(PREGS regs);
VOID VmExitMsrWriteHandler(PREGS regs);
VOID VmExitVmxHandler(PREGS regs);
BOOLEAN VmExitVmcallHandler(UINT64 vmcallNumber, UINT64 param1, UINT64 param2);
VOID SetupMsrBitmap(UINT64 msrBitmap);
BOOLEAN InitSegmentDescriptor(PUINT8 gdtBase, UINT16 segmentSelector, PSEGMENT_DESCRIPTOR segDesc);
BOOLEAN SetupGuestSelectorFields(PUINT8 gdtBase, UINT16 segmentSelector, UINT16 segmentSelectorIndex);
UINT32 AdjustVmcsControlField(UINT32 controls, ULONG msrAddr);
BOOLEAN SetupVmcs(PSYSTEM_DATA systemData, PUINT64 guestRSP);
UINT64* InitVmcsRegion();
VOID DeallocVmcsRegion(UINT64* vmcsRegionPhysical);
BOOLEAN AllocSystemData(PSYSTEM_DATA systemData);
VOID DeallocSystemData();
VOID WvsrVmExitHandler(PREGS guestRegs);
NTSTATUS WvsrCheckFeatures();
VOID WvsrDpcBroadcastVmxOnVm(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
NTSTATUS WvsrInitVm();
VOID WvsrDpcBroadcastStartVm(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
NTSTATUS WvsrStartVm(PUINT64 guestRSP);
VOID WvsrDpcBroadcastStopVm(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
VOID WvsrStopVm();
