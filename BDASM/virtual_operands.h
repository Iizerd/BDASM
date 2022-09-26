#pragma once

#include "obf.h"
#include "condition_code.h"

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

enum vm_operand_size_t : uint8_t { b8, b16, b32, b64, opsize_max };
enum vm_ireg_t : uint8_t { ireg1, ireg2, ireg3, ireg_max };

uint32_t vm_opsize_to_xed_opsize_map[4] = { 8, 16, 32, 64 };
register_width vm_opsize_to_register_width_map[4] = { register_width::byte, register_width::word, register_width::dword, register_width::qword };

constexpr uint32_t link_code_matrix_size = vm_ireg_t::ireg_max * vm_operand_size_t::opsize_max;

enum vm_iclass_t : uint16_t
{
	vm_enter,
	vm_exit,
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

#define link_code_define(_IClass) _IClass##_start, _IClass##_end = _IClass##_start + link_code_matrix_size - 1,

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

#define link_code(_IClass, _IReg, _OpSize) (vm_link_code_t::##_IClass##_start + (_IReg * vm_operand_size_t::opsize_max) + _OpSize)


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

	//addr_width::storage<aw>::type register_file[18];
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
namespace vinst_format
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
struct virtual_operands_t
{
	// All register sizes are the max for the addr_width that pass is invoked with.
	//

	//inline static uint32_t 

	// This is the global handler list that holds ALL handlers within.
	// It is slowly filled as more handlers are discovered and used.
	inline static dasm::inst_list_t<aw> handler_insts;

	inline static dasm::linker_t vm_linker = { 0 };

	inline static xed_reg_enum_t vmcs_reg, vip_reg;

	inline static xed_reg_enum_t iregs[vm_ireg_t::ireg_max];

	inline static constexpr uint32_t free_reg_count = addr_width::register_count<aw>::value - (vm_ireg_t::ireg_max + 1/*rsp*/ + 1/*rdi*/ + 1/*rsi*/);
	inline static xed_reg_enum_t free_regs[free_reg_count];

	// These are the links to the virtual operand table.
	//
	inline static uint32_t virtual_operand_handler_link_table[vm_link_code_max] = { dasm::linker_t::invalid_link_value };

	struct inst_flag_t
	{
		inline static constexpr uint16_t none = 0;

		inline static constexpr uint16_t native = (1 << 1);

		inline static constexpr uint16_t virt = (1 << 2);

		// Calc the displacement from rip to target a and put in disp
		//
		inline static constexpr uint16_t disp = (1 << 3);

	};

#pragma pack(push,1)
	struct inst_t
	{
		uint16_t iclass;
		uint16_t flags;
		uint32_t length;
		uint32_t my_link;
		uint32_t used_link;
		union
		{
			vinst_format::nothing_t no_operands;
			vinst_format::reg_t reg;
			vinst_format::reg_disp_t reg_disp;
			vinst_format::reg_reg_scale_disp_t reg_reg_scale_disp;
			vinst_format::imm8_t imm8;
			vinst_format::imm16_t imm16;
			vinst_format::imm32_t imm32;
			vinst_format::imm64_t imm64;

			struct
			{
				uint8_t operand_count;
				register_width widths[vm_ireg_t::ireg_max];
			}native;
		}fmt;
		union
		{
			struct
			{
				vm_ireg_t ireg;
				vm_operand_size_t opsize;
			}virt;
			struct
			{

			}native;
		}edata;
	};
	static_assert(offsetof(inst_t, fmt.no_operands) == 0x10);
	static_assert(offsetof(inst_t, fmt.reg) == 0x10);
	static_assert(offsetof(inst_t, fmt.reg_disp) == 0x10);
	static_assert(offsetof(inst_t, fmt.reg_reg_scale_disp) == 0x10);
	static_assert(offsetof(inst_t, fmt.imm8) == 0x10);
	static_assert(offsetof(inst_t, fmt.imm16) == 0x10);
	static_assert(offsetof(inst_t, fmt.imm32) == 0x10);
	static_assert(offsetof(inst_t, fmt.imm64) == 0x10);
	//static_assert(sizeof(inst_t) == 0x20);
#pragma pack(pop)


	class block_t
	{
	public:
		std::list<inst_t> insts;

		std::list<block_t>::iterator fallthrough_block, taken_block;

		dasm::termination_type_t termination_type;
	};

	class routine_t
	{
	public:
		std::list<block_t> blocks;
	};


	/*uint32_t encode_inst(inst_t* inst, uint8_t* dest, obf::data_chunk_t<)
	{
		if (inst.flags & inst_flag_t::disp)
		{
			if (inst.type == vm_iclass_t::load_mem_bd || inst.type == vm_iclass_t::store_mem_bd)
			{
				inst.format.reg_disp.disp = static_cast<int32_t>(static_cast<int64_t>(vm_linker.get_link_addr(inst.used_link)) - static_cast<int64_t>(vm_linker.get_link_addr(inst.my_link)));
			}
			else if (inst.type == vm_iclass_t::load_mem_bisd || inst.type == vm_iclass_t::store_mem_bisd)
			{
				inst.format.reg_reg_scale_disp.disp = static_cast<int32_t>(static_cast<int64_t>(vm_linker.get_link_addr(inst.used_link)) - static_cast<int64_t>(vm_linker.get_link_addr(inst.my_link)));
			}
			else if (inst.type == vm_iclass_t::load_imm)
			{
				if (inst.length == sizeof(vinst_format::imm32_t))
				{
					inst.format.imm32.disp = static_cast<int32_t>(static_cast<int64_t>(vm_linker.get_link_addr(inst.used_link)) - static_cast<int64_t>(vm_linker.get_link_addr(inst.my_link)));
				}
				else if (inst.length == sizeof(vinst_format::imm64_t))
				{
					inst.format.imm64.disp = static_cast<int64_t>(static_cast<int64_t>(vm_linker.get_link_addr(inst.used_link)) - static_cast<int64_t>(vm_linker.get_link_addr(inst.my_link)));
				}
				else
					return 0;
			}
			else
				return 0;
		}

		std::memcpy(dest, &inst.format.no_operands, inst.length);

		return inst.length;
	}*/


	template<addr_width::type aw = addr_width::x64>
	inline static void emit_native_inst(dasm::linker_t& linker, dasm::inst_t<aw>& inst, std::list<inst_t>& dest)
	{
		auto iclass = inst.iclass();
		switch (iclass)
		{/*
		case XED_ICLASS_PUSHF:
		case XED_ICLASS_PUSHFD:
		case XED_ICLASS_PUSHFQ:
		case XED_ICLASS_POPF:
		case XED_ICLASS_POPFD:
		case XED_ICLASS_POPFQ:*/

		case XED_ICLASS_CALL_NEAR:
		case XED_ICLASS_RET_NEAR:

		case XED_ICLASS_JB:
		case XED_ICLASS_JBE:
		case XED_ICLASS_JCXZ:
		case XED_ICLASS_JECXZ:
		case XED_ICLASS_JL:
		case XED_ICLASS_JLE:
		case XED_ICLASS_JMP:
		case XED_ICLASS_JMP_FAR:
		case XED_ICLASS_JNB:
		case XED_ICLASS_JNBE:
		case XED_ICLASS_JNL:
		case XED_ICLASS_JNLE:
		case XED_ICLASS_JNO:
		case XED_ICLASS_JNP:
		case XED_ICLASS_JNS:
		case XED_ICLASS_JNZ:
		case XED_ICLASS_JO:
		case XED_ICLASS_JP:
		case XED_ICLASS_JRCXZ:
		case XED_ICLASS_JS:
		case XED_ICLASS_JZ:

			printf("unhandled major instruction.\n");
			break;

		default:

			inst_t& ninst = dest.emplace_back();
			ninst.flags |= inst_flag_t::native;
			ninst.my_link = linker.allocate_link();
			ninst.used_link = dasm::linker_t::invalid_link_value;
			ninst.iclass = iclass;
			ninst.length = sizeof vinst_format::nothing_t;
			ninst.fmt.native.operand_count = 0;
			
			auto _inst = inst.inst();
			auto _noperands = inst.noperands();
			for (uint32_t i = 0; i < _noperands; ++i)
			{
				auto operand = xed_inst_operand(_inst, i);
				if (XED_OPVIS_EXPLICIT == xed_operand_operand_visibility(operand))
				{
					ninst.fmt.native.widths[ninst.fmt.native.operand_count++] = static_cast<register_width>(inst.operand_length(i));
				}
			}

			break;
		}
	}
	
	template<addr_width::type aw = addr_width::x64>
	inline static void emit_generic_prologue_epilogue(dasm::linker_t& linker, dasm::inst_t<aw>& inst, std::list<inst_t>& prologue, std::list<inst_t>& epilogue)
	{
		auto num_operands = inst.noperands();
		auto inst_inst = inst.inst();
		uint32_t ireg_idx = vm_ireg_t::ireg1;

		for (uint32_t i = 0; i < num_operands; ++i)
		{
			auto operand = xed_inst_operand(inst_inst, i);

			if (XED_OPVIS_EXPLICIT != xed_operand_operand_visibility(operand))
				continue;

			if (xed_operand_read(operand))
			{
				inst_t& vinst = prologue.emplace_back();
				vinst.flags = inst_flag_t::virt;
				vinst.edata.virt.ireg = static_cast<vm_ireg_t>(ireg_idx);
				vinst.edata.virt.opsize = static_cast<vm_operand_size_t>(inst.operand_length(i));
				vinst.my_link = linker.allocate_link();
				vinst.used_link = dasm::linker_t::invalid_link_value;
				
				auto operand_name = xed_operand_name(operand);
				if (xed_operand_is_register(operand_name))
				{
					vinst.iclass = vm_iclass_t::load_reg;
					vinst.length = sizeof vinst_format::reg_t;
					vinst.fmt.reg.reg1 = __reg_enum_to_internal_id(inst.get_reg(operand_name));
				}
				else if (operand_name == XED_OPERAND_MEM0)
				{
					auto base = inst.get_base_reg(0);
					auto index = inst.get_index_reg(0);
					auto scale = inst.get_scale(0);
					auto disp = inst.get_memory_displacement(0);

					if (index != XED_REG_INVALID)
					{
						vinst.iclass = vm_iclass_t::load_mem_bisd;
						vinst.length = sizeof vinst_format::reg_reg_scale_disp_t;
						vinst.fmt.reg_reg_scale_disp.reg1 = __reg_enum_to_internal_id(base);
						vinst.fmt.reg_reg_scale_disp.reg2 = __reg_enum_to_internal_id(index);
						vinst.fmt.reg_reg_scale_disp.scale = scale / 2;
						vinst.fmt.reg_reg_scale_disp.disp = disp;
					}
					else if (disp != 0)
					{
						vinst.iclass = vm_iclass_t::load_mem_bd;
						vinst.length = sizeof vinst_format::reg_disp_t;
						vinst.fmt.reg_disp.reg1 = __reg_enum_to_internal_id(base);
						vinst.fmt.reg_disp.disp = disp;
					}
					else
					{
						vinst.iclass = vm_iclass_t::load_mem_b;
						vinst.length = sizeof vinst_format::reg_t;
						vinst.fmt.reg.reg1 = __reg_enum_to_internal_id(base);
					}

				}
				else if (operand_name == XED_OPERAND_IMM0)
				{
					vinst.iclass = vm_iclass_t::load_imm;
					vinst.length = sizeof vinst_format::imm64_t;
					vinst.edata.virt.opsize = vm_operand_size_t::b64;
					vinst.fmt.imm64.simm = inst.get_signed_immediate();
				}
				else if (operand_name == XED_OPERAND_IMM0SIGNED)
				{
					vinst.iclass = vm_iclass_t::load_imm;
					vinst.length = sizeof vinst_format::imm64_t;
					vinst.edata.virt.opsize = vm_operand_size_t::b64;
					vinst.fmt.imm64.simm = inst.get_unsigned_immediate();
				}
			}
			if (xed_operand_written(operand))
			{
				inst_t& vinst = epilogue.emplace_back();
				vinst.flags = inst_flag_t::virt;
				vinst.edata.virt.ireg = static_cast<vm_ireg_t>(ireg_idx);
				vinst.edata.virt.opsize = static_cast<vm_operand_size_t>(inst.operand_length(i));
				vinst.my_link = linker.allocate_link();
				vinst.used_link = dasm::linker_t::invalid_link_value;

				auto operand_name = xed_operand_name(operand);
				if (xed_operand_is_register(operand_name))
				{
					vinst.iclass = vm_iclass_t::store_reg;
					vinst.length = sizeof vinst_format::reg_t;
					vinst.fmt.reg.reg1 = __reg_enum_to_internal_id(inst.get_reg(operand_name));
				}
				else if (operand_name == XED_OPERAND_MEM0)
				{
					auto base = inst.get_base_reg(0);
					auto index = inst.get_index_reg(0);
					auto scale = inst.get_scale(0);
					auto disp = inst.get_memory_displacement(0);

					if (index != XED_REG_INVALID)
					{
						vinst.iclass = vm_iclass_t::store_mem_bisd;
						vinst.length = sizeof vinst_format::reg_reg_scale_disp_t;
						vinst.fmt.reg_reg_scale_disp.reg1 = __reg_enum_to_internal_id(base);
						vinst.fmt.reg_reg_scale_disp.reg2 = __reg_enum_to_internal_id(index);
						vinst.fmt.reg_reg_scale_disp.scale = scale / 2;
						vinst.fmt.reg_reg_scale_disp.disp = disp;
					}
					else if (disp != 0)
					{
						vinst.iclass = vm_iclass_t::store_mem_bd;
						vinst.length = sizeof vinst_format::reg_disp_t;
						vinst.fmt.reg_disp.reg1 = __reg_enum_to_internal_id(base);
						vinst.fmt.reg_disp.disp = disp;
					}
					else
					{
						vinst.iclass = vm_iclass_t::store_mem_b;
						vinst.length = sizeof vinst_format::reg_t;
						vinst.fmt.reg.reg1 = __reg_enum_to_internal_id(base);
					}

				}
			}

			++ireg_idx;
		}
	}

	template<addr_width::type aw = addr_width::x64>
	inline static std::list<inst_t> translate_instruction(dasm::linker_t& linker, dasm::inst_t<aw>& inst)
	{
		std::list<inst_t> prologue, epilogue;

		emit_generic_prologue_epilogue(linker, inst, prologue, epilogue);

		emit_native_inst(linker, inst, prologue);

		prologue.splice(prologue.end(), epilogue);

		return prologue;
	}

	// Actual conversion from x86 to the vm instructions
	//
	template<addr_width::type aw = addr_width::x64>
	inline static std::list<block_t>::iterator convert_basic_block(dasm::linker_t& linker, routine_t& routine, dasm::block_it_t<aw> block)
	{
		routine.blocks.emplace_front();
		auto vm_block = routine.blocks.begin();
		vm_block->termination_type = block->termination_type;
		for (auto& inst : block->instructions)
		{
			vm_block->insts.splice(vm_block->insts.end(), translate_instruction(linker, inst));
		}

		switch (block->termination_type)
		{
		case dasm::termination_type_t::unconditional_br:
			vm_block->taken_block = convert_basic_block(linker, routine, block->taken_block);
			break;
		case dasm::termination_type_t::conditional_br:
			vm_block->taken_block = convert_basic_block(linker, routine, block->taken_block);
			[[fallthrough]];
		case dasm::termination_type_t::fallthrough:
			vm_block->fallthrough_block = convert_basic_block(linker, routine, block->fallthrough_block);
			break;
		}



		return vm_block;
	}

	// Couple of things that need to happen here:
	//
	//   Find the links needed for the terminators for each block, properly resolve/set them
	//   Allocate and set all handler indices.
	//
	template<addr_width::type aw = addr_width::x64>
	inline static void prep_for_encoding(obf::obf_t<aw>& ctx, routine_t& routine)
	{
		
	}

	template<addr_width::type aw = addr_width::x64>
	inline static void place_basic_block(obf::obf_t<aw>& ctx, block_t& block, uint64_t& rva)
	{
		for (inst_t& inst : block.insts)
		{
			ctx.linker->set_link_addr(inst.my_link, rva);
			rva += inst.length;
		}
	}

	template<addr_width::type aw = addr_width::x64>
	inline static uint32_t emit_basic_block(block_t& block, obf::data_chunk_t<aw>& data_chunk)
	{
		for (inst_t& inst : block.insts)
		{
			auto rva = data_chunk.raw_data.size();
			data_chunk.raw_data.insert(data_chunk.raw_data.end(), inst.length, 0);
			std::memcpy(data_chunk.raw_data.data() + rva, &inst.fmt, inst.length);
		}
	}

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


	// This is the epilogue that gets appended to all handlers and increments ip
	//
	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_handler_epilogue(obf::obf_t<aw>& ctx, uint32_t inst_length)
	{
		// This is the same type of virtual inst prologue i used in my very first vm
		// https://github.com/Iizerd/VirtualMachine/blob/main/DynamicGenerator/StackMachine.asm#L26
		// First it increments rip by the provided amount, then perfoms a jump
		//

		dasm::inst_list_t<aw> result;

		if (inst_length)
		{
			result.emplace_back(
				XED_ICLASS_ADD,
				addr_width::bits<aw>::value,
				xed_reg(vip_reg),
				xed_imm0(inst_length, 8)
			).common_edit(ctx.linker->allocate_link(), 0, 0);
		}

		// Have to do this because rip relative instructions need to access vip
		// So store vip into the ip register in vmcs
		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_mem_bd(
				vmcs_reg,
				xed_disp(offsetof(vmcs_t<aw>, ip), 32),
				addr_width::bits<aw>::value
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

	// Enter and exit
	///
	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_vmenter(obf::obf_t<aw>& ctx, uint32_t vmcs_link, uint32_t vip_link)
	{
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
		dasm::inst_list_t<aw> result;

		result.emplace_back(XED_ICLASS_PUSH, addr_width::bits<aw>::value, xed_reg(max_reg_width<XED_REG_RDI, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_LEA, addr_width::bits<aw>::value, xed_reg(max_reg_width<XED_REG_RDI, aw>::value), xed_mem_bd(max_reg_width<XED_REG_RIP, aw>::value, xed_disp(0, 32), addr_width::bits<aw>::value)).common_edit(ctx.linker->allocate_link(), vmcs_link, dasm::inst_flag::disp);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, a), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RAX, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, b), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RBX, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, c), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RCX, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, d), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RDX, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, sp), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RSP, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, bp), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RBP, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, si), 32), addr_width::bits<aw>::value), xed_reg(max_reg_width<XED_REG_RSI, aw>::value)).common_edit(ctx.linker->allocate_link(), 0, 0);
		
		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r8), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R8)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r9), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R9)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r10), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R10)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r11), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R11)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r12), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R12)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r13), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R13)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r14), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R14)).common_edit(ctx.linker->allocate_link(), 0, 0);
			result.emplace_back(XED_ICLASS_MOV, addr_width::bits<aw>::value, xed_mem_bd(max_reg_width<XED_REG_RDI, aw>::value, xed_disp(offsetof(vmcs_t<aw>, r15), 32), addr_width::bits<aw>::value), xed_reg(XED_REG_R15)).common_edit(ctx.linker->allocate_link(), 0, 0);
		}

		result.emplace_back(
			XED_ICLASS_POP,
			addr_width::bits<aw>::value,
			xed_mem_bd(
				max_reg_width<XED_REG_RDI, aw>::value, 
				xed_disp(offsetof(vmcs_t<aw>, di), 32), 
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<aw>::value,
			xed_reg(max_reg_width<XED_REG_RSI, aw>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, aw>::value, 
				xed_disp(0, 32), 
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), vip_link, dasm::inst_flag::disp);

		result.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<aw>::value,
			xed_reg(max_reg_width<XED_REG_RSP, aw>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RDI, aw>::value,
				xed_disp(offsetof(vmcs_t<aw>, flags), 8),
				addr_width::bits<aw>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_PUSHF,
			addr_width::bits<aw>::value
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, 0));

		return result;

	}
	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_vmexit(obf::obf_t<aw>& ctx)
	{

	}

	// These are the default vm instructions that are used to load/store from the iregs
	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_reg_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(vinst_format::reg_t, reg1)]
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
				xed_disp(offsetof(vinst_format::reg_t, reg1), 8),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_reg_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(vinst_format::reg_t, reg1)]
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
				xed_disp(offsetof(vinst_format::reg_t, reg1), 8),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_mem_b_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(vinst_format::reg_t, reg1)]
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
				xed_disp(offsetof(vinst_format::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_mem_b_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(vinst_format::reg_t, reg1)]
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
				xed_disp(offsetof(vinst_format::reg_t, reg1), 8),
				8
			)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<aw>::value,
			xed_reg(reg_idx),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_mem_bd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(vinst_format::reg_disp_t, reg1)]
		// movsxd reg_disp,dword ptr[vip+offsetof(vinst_format::reg_disp_t, disp)]
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
				xed_disp(offsetof(vinst_format::reg_disp_t, reg1), 8),
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
					xed_disp(offsetof(vinst_format::reg_disp_t, disp), 8),
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
					xed_disp(offsetof(vinst_format::reg_disp_t, disp), 8),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_disp_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_mem_bd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_idx,[vip+offsetof(vinst_format::reg_disp_t, reg1)]
		// movsxd reg_disp,dword ptr[vip+offsetof(vinst_format::reg_disp_t, disp)]
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
				xed_disp(offsetof(vinst_format::reg_disp_t, reg1), 8),
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
					xed_disp(offsetof(vinst_format::reg_disp_t, disp), 8),
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
					xed_disp(offsetof(vinst_format::reg_disp_t, disp), 8),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_disp_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_load_mem_bisd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_tmp,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, reg2)]		; First load the idx register
		// mov reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// mov reg_tmp,rcx
		// mov cl,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, scale)]			; Load the scale amount
		// shl reg_acc,cl																; Shift index register by the scale amount
		// mov rcx,reg_tmp
		// movzx reg_tmp,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, reg1)]		; Load the base register
		// add reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// movsxd reg_tmp,dword ptr[vip+offsetof(vinst_format::reg_disp_t, disp)]		; Load the displacement
		// add reg_acc,reg_tmp	
		//
		
		dasm::inst_list_t<aw> result;

		auto [reg_tmp, reg_acc] = get_two_free_regs();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, reg2), 8),
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
				xed_disp(vmcs_register_file(aw), 8),
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
				xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, scale), 8),
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

		// movzx reg_tmp,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, reg1)]		; Load the base register
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, reg1), 8),
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

		// movsxd reg_tmp,dword ptr[vip+offsetof(vinst_format::reg_reg_scale_disp_t, disp)]		; Load the displacement
		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(
				XED_ICLASS_MOVSXD,
				addr_width::bits<aw>::value,
				xed_reg(reg_tmp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, disp), 8),
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
					xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, disp), 8),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_reg_scale_disp_t));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_store_mem_bisd_handler(obf::obf_t<aw>& ctx, vm_ireg_t ireg, vm_operand_size_t op_size)
	{
		// movzx reg_tmp,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, reg2)]		; First load the idx register
		// mov reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// mov reg_tmp,rcx
		// mov cl,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, scale)]			; Load the scale amount
		// shl reg_acc,cl																; Shift index register by the scale amount
		// mov rcx,reg_tmp
		// movzx reg_tmp,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, reg1)]		; Load the base register
		// add reg_acc,qword ptr[vmcs+reg_tmp*8+vmcs_register_file(aw)]
		// movsxd reg_tmp,dword ptr[vip+offsetof(vinst_format::reg_disp_t, disp)]		; Load the displacement
		// add reg_acc,reg_tmp	
		//

		dasm::inst_list_t<aw> result;

		auto [reg_tmp, reg_acc] = get_two_free_regs();

		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, reg2), 8),
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
				xed_disp(vmcs_register_file(aw), 8),
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
				xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, scale), 8),
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

		// movzx reg_tmp,[vip+offsetof(vinst_format::reg_reg_scale_disp_t, reg1)]		; Load the base register
		result.emplace_back(
			XED_ICLASS_MOVZX,
			addr_width::bits<aw>::value,
			xed_reg(reg_tmp),
			xed_mem_bd(
				vip_reg,
				xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, reg1), 8),
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

		// movsxd reg_tmp,dword ptr[vip+offsetof(vinst_format::reg_reg_scale_disp_t, disp)]		; Load the displacement
		if constexpr (aw == addr_width::x64)
		{
			result.emplace_back(
				XED_ICLASS_MOVSXD,
				addr_width::bits<aw>::value,
				xed_reg(reg_tmp),
				xed_mem_bd(
					vip_reg,
					xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, disp), 8),
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
					xed_disp(offsetof(vinst_format::reg_reg_scale_disp_t, disp), 8),
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

		result.splice(result.end(), build_handler_epilogue(ctx, sizeof vinst_format::reg_reg_scale_disp_t));

		return result;
	}

	


	// These are specific handlers that cant be generated trivially and must be hand built
	//
	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_jcc(obf::obf_t<aw>& ctx, xed_iclass_enum_t jcc)
	{
		// This instruction assumes that the displacements required have been moved into the two iregs
		// ireg1 = fallthrough displacement
		// ireg2 = taken displacement
		//

		// cmovcc ireg1,ireg2
		// add vip_reg,ireg1
		// epilogue with zero rip advancement

		dasm::inst_list_t<aw> result;

		result.emplace_back(
			xed_condition_code_to_cmovcc(xed_iclass_to_condition_code(jcc)),
			addr_width::bits<aw>::value,
			xed_reg(iregs[ireg1]),
			xed_reg(iregs[ireg2])
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<aw>::value,
			xed_reg(vip_reg),
			xed_reg(iregs[ireg1])
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.splice(result.end(), build_handler_epilogue(ctx, 0));

		return result;
	}

	template<addr_width::type aw = addr_width::x64>
	inline static dasm::inst_list_t<aw> build_call(obf::obf_t<aw>& ctx)
	{
		// Keep in mind this instruction must exit the vm completely, release the spinlock, and THEN perform the call
		//

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
	inline static void initialize_tables()
	{
		iregs[vm_ireg_t::ireg1] = max_reg_width<XED_REG_RAX, aw>::value;
		iregs[vm_ireg_t::ireg2] = max_reg_width<XED_REG_RCX, aw>::value;
		iregs[vm_ireg_t::ireg3] = max_reg_width<XED_REG_RDX, aw>::value;

		vmcs_reg = max_reg_width<XED_REG_RDI, aw>::value;
		vip_reg = max_reg_width<XED_REG_RSI, aw>::value;

		if constexpr (aw == addr_width::x64)
		{
			free_regs[0] = XED_REG_RBX;
			//free_regs[1] = XED_REG_RDX;
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
			//free_regs[1] = XED_REG_EDX;
			free_regs[2] = XED_REG_EBP;
		}

	}
};
