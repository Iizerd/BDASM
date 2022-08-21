#pragma once

#include "obf.h"

// Ok so the basic idea behind this is that we move all the registers out into a structure somewhere in memory
// The vm is protected by a spinlock like themida until i figure out tls stuff.
// All instructions are transformed from their original iform into one that uses exclusively some "internal registers"
// 
// 
// 	General structure:
//		
//		rdi: vm control structure(vmcs) and saved registers
//		rsi: virtual instruction pointer
//		rsp: points to place inside vmcs where flags are stored during prologue and epilogue
//		rax,rbx,rcx: internal registers used in calculations
//		
// 
// Imagine the instruction:
//	
//		add r11,r12
// 
//	The virtual instruction using the internal registers is:
// 
//		add rax,rbx
// 
//	So we need both a prologue and epilogue where the stored r11 and r12 and moved into the internal registers.
//	For this example it would look something like this:
// 
//		ViLoadVirtReg64:
//			mov rax,[rdi+vmcs.r11]
//		ViLoadVirtReg64:
//			mov rbx,[rdi+vmcs.r12]
//		ViLoadNativeFlags:	// This can be skipped if the instruction doesnt modify flags
//			popfq
//		ViAddQ
//			add rax,rbx
//		ViStoreNativeFlags:
//			pushfq
//		ViStoreVirtReg64:
//			mov [rdi+vmcs.r11],rax
// 
//	A total of 6 virtual instructions for this one x86 instruction.
//			
//	
//	vm_enter:
//		acquire_vmcs_spinlock
// 
//		mov [vmcs.a],rax			; probably randomize the order of these to break basic pattern?
//		mov ...
//		mov [vmcs.r15],r15
//		
//		lea rsp,[vmcs.flags]		; load flag storage into rsp
//		pushfq						; store the native flags
//		lea rdi,[vmcs]				; load vmcs into rdi
//		
//		lea rsi,[vip]
//		jmp qword ptr[rdi+rsi*4+sizeof(vmcs)]
//

enum default_vm_iform_t : uint16_t
{
	load_reg_8,
	load_reg_16,
	load_reg_32,
	load_reg_64,

	store_reg_8,
	store_reg_16,
	store_reg_32,
	store_reg_64,

	load_mem_b_8,
	load_mem_b_16,
	load_mem_b_32,
	load_mem_b_64,

	store_mem_b_8,
	store_mem_b_16,
	store_mem_b_32,
	store_mem_b_64,

	load_mem_bd_8,
	load_mem_bd_16,
	load_mem_bd_32,
	load_mem_bd_64,

	store_mem_bd_8,
	store_mem_bd_16,
	store_mem_bd_32,
	store_mem_bd_64,

	load_mem_bisd_8,
	load_mem_bisd_16,
	load_mem_bisd_32,
	load_mem_bisd_64,

	store_mem_bisd_8,
	store_mem_bisd_16,
	store_mem_bisd_32,
	store_mem_bisd_64,
};


#pragma pack(push,1)

struct vmcs_t
{
	uint64_t spinlock;
	uint64_t flags;
	union
	{
		uint64_t a, b, c, d, sp, bp, si, di,
			r8, r9, r10, r11, r12, r13, r14, r15;
		uint64_t regs[16];
	};
	//uint32_t handler_table[1];
};

// The four possible forms for the operand manipulation handlers
//
struct inst_nothing_t
{
	uint16_t opcode;
};

struct inst_reg_t
{
	uint16_t opcode;
	uint8_t reg1;
};

struct inst_reg_disp_t
{
	uint16_t opcode;
	uint8_t reg1;
	int32_t disp;
};

struct inst_reg_reg_scale_disp_t
{
	uint16_t opcode;
	uint8_t reg1;
	uint8_t reg2;
	uint8_t scale;
	int32_t disp;
};

#pragma pack(pop)


struct flatten_control_flow_t
{
	inline static xed_reg_enum_t 
		vmcs_reg,
		vip_reg,
		intern_reg1,
		intern_reg2,
		intern_reg3;









};
