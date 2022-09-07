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
//		rax,rcx: internal registers used in calculations
//		rcx: reserved for internal shift operations
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
enum vm_ireg_t : uint32_t { ireg1, ireg2, /*ireg3,*/ ireg_max };

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

template<addr_width::type aw = addr_width::x64>
struct vmcs_t
{
	uint64_t spinlock;
	uint64_t flags;

	addr_width::storage<aw>::type a, b, c, d, sp, bp, si, di,
		r8, r9, r10, r11, r12, r13, r14, r15, ip, pad;
	//uint32_t handler_table[1];
};
static_assert(sizeof(vmcs_t<addr_width::x64>) % 8 == 0 && sizeof(vmcs_t<addr_width::x86>) % 8 == 0);

#define vmcs_register_file(_Addr_width) offsetof(vmcs_t<_Addr_width>, a)
#define vmcs_handler_table(_Addr_width) sizeof(vmcs_t<_Addr_width>)

// Here are the 8 different possible instruction encodings.
// ranging from 2 to 16 bytes in size
//
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

	struct imm8_t
	{
		uint16_t opcode;
		uint8_t pad;
		union { uint8_t imm; int8_t simm; };
	};
	static_assert(sizeof(imm8_t) % 2 == 0);

	struct imm16_t
	{
		uint16_t opcode;
		union { uint16_t imm; int16_t simm; };
	};
	static_assert(sizeof(imm16_t) % 2 == 0);
	static_assert(offsetof(imm16_t, imm) % 2 == 0);

	struct imm32_t
	{
		uint16_t opcode;
		uint16_t pad;
		union { uint32_t imm; int32_t simm; };
	};
	static_assert(sizeof(imm32_t) % 2 == 0);
	static_assert(offsetof(imm32_t, imm) % 4 == 0);

	struct imm64_t
	{
		uint16_t opcode;
		uint16_t pad[3];
		union { uint64_t imm; int64_t simm; };
	};
	static_assert(sizeof(imm64_t) % 2 == 0);
	static_assert(offsetof(imm64_t, imm) % 8 == 0);

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


	finline static xed_reg_enum_t get_free_reg()
	{
		return free_regs[rand() % free_reg_count];
	}
	finline static std::tuple<xed_reg_enum_t, xed_reg_enum_t> get_two_free_regs()
	{
		static_assert(free_reg_count > 1, "There are not two free registers.");

		auto first = rand() % free_reg_count;
		auto second = first + 1;
		if (second >= free_reg_count)
			second = 0;

		return { free_regs[first], free_regs[second] };
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_handler_epilogue(obf::obf_t<aw>& ctx, uint32_t inst_length)
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

		// Have to do this because rip relative instructions need to access vip
		// So store vip into the ip register in vmcs
		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_mem_bd(
				vmcs_reg,
				xed_disp(offsetof(vmcs_t<aw>, rip), 32),
				8
			),
			xed_reg(vip_reg)
		).common_edit(ctx.linker->allocate_link(), 0, 0);
		
		auto [idx_reg, other_reg] = get_two_free_regs();

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
				xed_disp(vmcs_handler_table(aw), 32),
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
		// movzx reg_idx,[vip+offsetof(virt_insts::reg_t, reg1)]
		// size ptr[vmcs+reg_idx*8+vmcs_register_file(aw)],ireg
		//

		dasm::inst_list_t<aw> result;

		auto reg_idx = get_free_reg();
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
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
			xed_mem_bisd(
				vmcs_reg,
				reg_idx,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				vm_opsize_to_xed_opsize_map[op_size]
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_reg_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(virt_insts::reg_t, reg1)]
		// ireg,size ptr[vmcs+reg_idx*8+vmcs_register_file(aw)]
		//

		dasm::inst_list_t<aw> result;

		auto reg_idx = get_free_reg();
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			vm_opsize_to_xed_opsize_map[op_size],
			xed_mem_bisd(
				vmcs_reg,
				reg_idx,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				vm_opsize_to_xed_opsize_map[op_size]
			),
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size]))
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_mem_b_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(virt_insts::reg_t, reg1)]
		// mov reg_idx,qword ptr[vmcs+reg_idx*8+vmcs_register_file(aw)]
		// mov ireg,size ptr[reg_idx]
		// 

		dasm::inst_list_t<aw> result;

		auto op_size_bits = vm_opsize_to_xed_opsize_map[op_size];
		auto reg_idx = get_free_reg();
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx)
			xed_mem_bisd(
				vmcs_reg,
				reg_idx,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			op_size_bits,
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size])),
			xed_mem_b(reg_idx, op_size_bits)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_mem_b_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(virt_insts::reg_t, reg1)]
		// mov reg_idx,qword ptr[vmcs+reg_idx*8+vmcs_register_file(aw)]
		// mov size ptr[reg_idx],ireg
		// 

		dasm::inst_list_t<aw> result;

		auto op_size_bits = vm_opsize_to_xed_opsize_map[op_size];
		auto reg_idx = get_free_reg();
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx)
			xed_mem_bisd(
				vmcs_reg,
				reg_idx,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			op_size_bits,
			xed_mem_b(reg_idx, op_size_bits),
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size]))
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_mem_bd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(virt_insts::reg_disp_t, reg1)]
		// movsxd reg_disp,dword ptr[vip+offsetof(virt_insts::reg_disp_t, disp)]
		// add reg_disp,qword ptr[vmcs+reg_idx*8+vmcs_register_file(aw)]
		// mov ireg,size ptr[reg_disp]
		// 

		dasm::inst_list_t<aw> result;

		auto op_size_bits = vm_opsize_to_xed_opsize_map[op_size];
		auto [reg_idx, reg_disp] = get_two_free_regs();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_disp_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(
				XED_ICLASS_MOVSXD,
				addr_width::bits<aw>::value,
				xed_reg(reg_disp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}
		if constexpr (aw == addr_width::x86)
		{
			result.emplace_back(
				XED_ICLASS_MOV,
				addr_width::bits<aw>::value,
				xed_reg(reg_disp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(reg_disp),
			xed_mem_bisd(
				vmcs_reg,
				reg_idx,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			op_size_bits,
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size])),
			xed_mem_b(reg_disp, op_size_bits)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_disp_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_mem_bd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(virt_insts::reg_disp_t, reg1)]
		// movsxd reg_disp,dword ptr[vip+offsetof(virt_insts::reg_disp_t, disp)]
		// add reg_disp,qword ptr[vmcs+reg_idx*8+vmcs_register_file(aw)]
		// mov size ptr[reg_disp],ireg
		// 

		dasm::inst_list_t<aw> result;

		auto op_size_bits = vm_opsize_to_xed_opsize_map[op_size];
		auto [reg_idx, reg_disp] = get_two_free_regs();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_disp_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(
				XED_ICLASS_MOVSXD,
				addr_width::bits<aw>::value,
				xed_reg(reg_disp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}
		if constexpr (aw == addr_width::x86)
		{
			result.emplace_back(
				XED_ICLASS_MOV,
				addr_width::bits<aw>::value,
				xed_reg(reg_disp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(reg_disp),
			xed_mem_bisd(
				vmcs_reg,
				reg_idx,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			op_size_bits,
			xed_mem_b(reg_disp, op_size_bits),
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size]))
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_disp_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_mem_bisd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_tmp,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, reg2)]		; First load the idx register
		// mov reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// mov reg_tmp,rcx
		// mov cl,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, scale)]			; Load the scale amount
		// shl reg_acc,cl																; Shift index register by the scale amount
		// mov rcx,reg_tmp
		// movzx reg_tmp,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, reg1)]		; Load the base register
		// add reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// movsxd reg_tmp,dword ptr[vip+offsetof(virt_insts::reg_disp_t, disp)]		; Load the displacement
		// add reg_acc,reg_tmp	
		//
		
		dasm::inst_list_t<aw> result;

		auto [reg_tmp, reg_acc] = get_free_reg();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_mem_bisd(
				vmcs_reg,
				reg_tmp,
				8,
				xed_disp(vmcs_register_file, 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_reg(max_reg_width<XED_REG_RCX, aw>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(XED_REG_CL),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, scale), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_SHL,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_reg(XED_REG_CL)
		).common_edit(ctx.linker->allocate_link(), 0, 0);


		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(max_reg_width<XED_REG_RCX, aw>::value),
			xed_reg(reg_tmp)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		// movzx reg_tmp,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, reg1)]		; Load the base register
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		// add reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_mem_bisd(
				vmcs_reg,
				reg_tmp,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		// movsxd reg_tmp,dword ptr[vip+offsetof(virt_insts::reg_reg_scale_disp_t, disp)]		; Load the displacement
		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(
				XED_ICLASS_MOVSXD,
				addr_width::bits<aw>::value,
				xed_reg(reg_tmp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}
		if constexpr (aw == addr_width::x86)
		{
			result.emplace_back(
				XED_ICLASS_MOV,
				addr_width::bits<aw>::value,
				xed_reg(reg_tmp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_reg(reg_tmp)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			vm_opsize_to_xed_opsize_map[op_size],
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size])),
			xed_mem_b(reg_acc, vm_opsize_to_xed_opsize_map[op_size])
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_reg_scale_disp_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_mem_bisd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_tmp,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, reg2)]		; First load the idx register
		// mov reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// mov reg_tmp,rcx
		// mov cl,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, scale)]			; Load the scale amount
		// shl reg_acc,cl																; Shift index register by the scale amount
		// mov rcx,reg_tmp
		// movzx reg_tmp,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, reg1)]		; Load the base register
		// add reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// movsxd reg_tmp,dword ptr[vip+offsetof(virt_insts::reg_disp_t, disp)]		; Load the displacement
		// add reg_acc,reg_tmp	
		//

		dasm::inst_list_t<aw> result;

		auto [reg_tmp, reg_acc] = get_free_reg();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_mem_bisd(
				vmcs_reg,
				reg_tmp,
				8,
				xed_disp(vmcs_register_file, 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_reg(max_reg_width<XED_REG_RCX, aw>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(XED_REG_CL),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, scale), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_SHL,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_reg(XED_REG_CL)
		).common_edit(ctx.linker->allocate_link(), 0, 0);


		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(max_reg_width<XED_REG_RCX, aw>::value),
			xed_reg(reg_tmp)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		// movzx reg_tmp,[vip+offsetof(virt_insts::reg_reg_scale_disp_t, reg1)]		; Load the base register
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		// add reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_mem_bisd(
				vmcs_reg,
				reg_tmp,
				8,
				xed_disp(vmcs_register_file(aw), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		// movsxd reg_tmp,dword ptr[vip+offsetof(virt_insts::reg_reg_scale_disp_t, disp)]		; Load the displacement
		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(
				XED_ICLASS_MOVSXD,
				addr_width::bits<aw>::value,
				xed_reg(reg_tmp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}
		if constexpr (aw == addr_width::x86)
		{
			result.emplace_back(
				XED_ICLASS_MOV,
				addr_width::bits<aw>::value,
				xed_reg(reg_tmp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(virt_insts::reg_reg_scale_disp_t, disp), 8),
					32
				)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(reg_acc),
			xed_reg(reg_tmp)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			vm_opsize_to_xed_opsize_map[op_size],
			xed_mem_b(reg_acc, vm_opsize_to_xed_opsize_map[op_size]),
			xed_reg(change_reg_width(iregs[ireg], vm_opsize_to_register_width_map[op_size]))
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof virt_insts::reg_reg_scale_disp_t));

		return result;
	}

	// If a handler manipulates the native flags, we need to load them so they can be edited
	//
	template<addr_width::type aw = addr_width::x64>
	inline static void wrap_handler_in_flag_load_store(obf::obf_t<aw>& ctx, dasm::inst_list_t<aw>& handler)
	{
		handler.emplace_front(
			XED_ICLASS_POPF,
			addr_width::bits<aw>::value
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		handler.emplace_back(
			XED_ICLASS_PUSHF,
			addr_width::bits<aw>::value
		).common_edit(ctx.linker->allocate_link(), 0, 0);
	}


	// This can be done randomly and programatically in the future
	//
	template<addr_width::type aw = addr_width::x64>
	void initialize_vm_regs()
	{
		iregs[vm_ireg_t::ireg1] = max_reg_width<XED_REG_RAX, aw>::value;
		iregs[vm_ireg_t::ireg2] = max_reg_width<XED_REG_RCX, aw>::value;

		vmcs_reg = max_reg_width<XED_REG_RDI, aw>::value;
		vip_reg = max_reg_width<XED_REG_RSI, aw>::value;

		if constexpr (aw == addr_width::x64)
		{
			free_regs[0] = XED_REG_RBX;
			free_regs[1] = XED_REG_RDX;
			free_regs[2] = XED_REG_RBP;
			free_regs[3] = XED_REG_R8;
			free_regs[4] = XED_REG_R9;
			free_regs[5] = XED_REG_R10;
			free_regs[6] = XED_REG_R11;
			free_regs[7] = XED_REG_R12;
			free_regs[8] = XED_REG_R13;
			free_regs[9] = XED_REG_R14;
			free_regs[10] = XED_REG_R15;
		}
		if constexpr (aw == addr_width::x86)
		{
			free_regs[0] = XED_REG_EBX;
			free_regs[1] = XED_REG_EDX;
			free_regs[2] = XED_REG_EBP;
		}

	}
};
