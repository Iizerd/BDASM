#pragma once

#include "obf.h"

// Ok so the basic idea behind this is that we move all the registers out into a structure somewhere in memory
// The vm is protected by a spinlock like themida until i figure out tls stuff.
// All instructions are transformed from their original iform into one that uses exclusively some "internal registers"
// 
// 
// 	General structure:
//		
//		rdi: vm control structure(vmcs) and saved registers, opcode table immediately follows
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

enum vm_operand_size_t : uint32_t { b8, b16, b32, b64, opsize_max };
enum vm_ireg_t : uint32_t { ireg1, ireg2, ireg3, ireg_max };

uint32_t vm_opsize_to_xed_opsize_map[4] = { 8, 16, 32, 64 };
register_width vm_opsize_to_register_width_map[4] = { register_width::byte, register_width::word, register_width::dword, register_width::qword };

constexpr uint32_t link_code_matrix_size = vm_ireg_t::ireg_max * vm_operand_size_t::opsize_max;

enum vm_iform_t
{
	load_reg,
	store_reg,
	load_mem_b,
	store_mem_b,
	load_mem_bd,
	store_mem_bd,
	load_mem_bisd,
	store_mem_bisd,
	load_imm,
};

#define link_code_define(_IForm) _IForm##_start, _IForm##_end = _IForm##_start + link_code_matrix_size - 1,

enum vm_link_code_t : uint32_t
{
	link_code_define(load_reg)
	link_code_define(store_reg)
	link_code_define(load_mem_b)
	link_code_define(store_mem_b)
	link_code_define(load_mem_bd)
	link_code_define(store_mem_bd)
	link_code_define(load_mem_bisd)
	link_code_define(store_mem_bisd)
	link_code_define(load_imm)
	vm_link_code_max
};

#define link_code(_IForm, _IReg, _OpSize) (vm_link_code_t::##_IForm##_start + (_IReg * vm_operand_size_t::opsize_max) + _OpSize)


// Despite this packing, everything has specific alignments.
// Instructions are aligned on 2 byte boundary to make sure access to opcodes is fine
// Displacements within instructions are aligned to 4 byte boundary.
//
#pragma pack(push,1)

struct vmcs_t
{
	uint64_t spinlock;
	uint64_t flags;
	uint64_t a, b, c, d, sp, bp, si, di,
		r8, r9, r10, r11, r12, r13, r14, r15;
	//uint32_t handler_table[1];
};
static_assert(sizeof(vmcs_t) % 8 == 0);

// Here are the four different possible forms for a virtual handler.
namespace virt_insts
{
	struct nothing_t
	{
		uint16_t opcode;
	};
	static_assert(sizeof(nothing_t) % 2 == 0);

	struct reg_t
	{
		uint16_t opcode;
		uint8_t reg1;
		uint8_t pad;
	};
	static_assert(sizeof(reg_t) % 2 == 0);

	struct reg_disp_t
	{
		uint16_t opcode;
		uint8_t reg1;
		uint8_t pad;
		int32_t disp;
	};
	static_assert(sizeof(reg_disp_t) % 2 == 0);
	static_assert(offsetof(reg_disp_t, disp) % 4 == 0);

	struct reg_reg_scale_disp_t
	{
		uint16_t opcode;
		uint8_t reg1;
		uint8_t reg2;
		uint8_t scale;
		uint8_t pad[3];
		int32_t disp;
	};
	static_assert(sizeof(reg_reg_scale_disp_t) % 2 == 0);
	static_assert(offsetof(reg_reg_scale_disp_t, disp) % 4 == 0);

}
#pragma pack(pop)

template<addr_width::type aw = addr_width::x64>
struct flatten_control_flow_t
{
	// All register sizes are the max for the addr_width that pass is invoked with.
	//

	inline static xed_reg_enum_t vmcs_reg, vip_reg;

	inline static xed_reg_enum_t iregs[vm_ireg_t::ireg_max];

	inline static constexpr uint32_t free_reg_count = addr_width::register_count<aw>::value - (vm_ireg_t::ireg_max + 1/*rsp*/ + 1/*rdi*/ + 1/*rsi*/);
	inline static xed_reg_enum_t free_regs[free_reg_count];

	// These are the links to the virtual operand table.
	//
	inline static uint32_t virtual_operand_handler_link_table[vm_link_code_max] = { dasm::linker_t::invalid_link_value };


	finline static xed_reg_enum_t get_random_free_reg()
	{
		return free_regs[rand() % free_reg_count];
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_handler_prologue(obf::obf_t<aw>& ctx, uint32_t inst_length)
	{
		// This is the same type of virtual inst prologue i used in my very first vm
		// https://github.com/Iizerd/VirtualMachine/blob/main/DynamicGenerator/StackMachine.asm#L26
		// First it increments rip by the provided amount, then perfoms a jump
		//

		dasm::inst_list_t<aw> result;

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(vip_reg),
			xed_imm0(inst_length, 8)
		).common_edit(ctx.linker->allocate_link(), 0, 0);
		
		auto idx_reg = get_random_free_reg();
		auto other_reg = get_random_free_reg();
		while (other_reg == idx_reg)
			other_reg = get_random_free_reg();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(idx_reg),
			xed_mem_b(vip_reg, 8)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<aw>::value,
			xed_reg(other_reg),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP,
				aw>::value,
				xed_disp(0, 32),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, dasm::inst_flag::disp);

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(other_reg),
			xed_mem_bisd(
				vmcs_reg,
				idx_reg,
				8,
				xed_disp(sizeof(vmcs_t), 32),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_JMP,
			addr_width::bits<aw>::value,
			xed_reg(other_reg)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_reg_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		dasm::inst_list_t<aw> result;

		auto reg = get_random_free_reg();
		auto reg_as_byte = change_reg_width(reg, register_width::byte);
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_as_byte),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			vm_opsize_to_xed_opsize_map[op_size],
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size])),
			xed_mem_bisd(vmcs_reg,
				reg,
				1,
				xed_disp(0, 8),
				64
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_prologue(ctx, sizeof(inst_reg_t)));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_reg_handler(vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		dasm::inst_list_t<aw> result;

		auto reg = get_random_free_reg();
		auto reg_as_byte = change_reg_width(reg, register_width::byte);
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_as_byte),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			vm_opsize_to_xed_opsize_map[op_size],
			xed_mem_bisd(vmcs_reg,
				reg,
				1,
				xed_disp(0, 8),
				64
			),
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size]))
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_prologue(ctx, sizeof(inst_reg_t)));

		return result;
	}





};
