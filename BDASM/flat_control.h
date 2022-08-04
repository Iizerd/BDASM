#pragma once


#include "obf.h"
#include "flags.h"
#include "condition_code.h"

// Rewrite jccs to use cmov and other more confusing logic
// This also makes all blocks position independent
//

// Invoking Gadget:
// 
//		push rax
//		push rbx
//		mov rax,not_taken_rva+adjustment
//		mov rbx,taken+adjustment
//		movcc rax,rbx
//		jmp gadget
//

// Gadget:
//		lea rax
//		mov not_taken_adjustment
//		sub rax,rbx
//		pop rbx
//		xchg [rsp],rax
//		ret
//		
//

inline bool first_gadgets_setup = false;

struct flatten_control_flow_t
{
	// Link for the gadget
	inline static uint32_t gadget_link[XED_CC_COMPAT_END];
	inline static uint32_t use_count[XED_CC_COMPAT_END];
	inline static int32_t taken_adjustment[XED_CC_COMPAT_END];
	inline static int32_t not_taken_adjustment[XED_CC_COMPAT_END];

	// Cant handle because there is no condition movcxz
	static bool jcxz(xed_iclass_enum_t iclass)
	{
		return !(iclass == XED_ICLASS_JCXZ ||
			iclass == XED_ICLASS_JECXZ ||
			iclass == XED_ICLASS_JRCXZ);
	}

	static uint8_t jcc_to_cc(xed_iclass_enum_t jcc)
	{
		switch (jcc)
		{
		case XED_ICLASS_JB: return 0;
		case XED_ICLASS_JBE: return 1;
		case XED_ICLASS_JL: return 2;
		case XED_ICLASS_JLE: return 3;
		case XED_ICLASS_JNB: return 4;
		case XED_ICLASS_JNBE: return 5;
		case XED_ICLASS_JNL: return 6;
		case XED_ICLASS_JNLE: return 7;
		case XED_ICLASS_JNO: return 8;
		case XED_ICLASS_JNP: return 9;
		case XED_ICLASS_JNS: return 10;
		case XED_ICLASS_JNZ: return 11;
		case XED_ICLASS_JO: return 12;
		case XED_ICLASS_JP: return 13;
		case XED_ICLASS_JS: return 14;
		case XED_ICLASS_JZ: return 15;
		default: return 16;
		}
	}

	static uint8_t invert_cc(uint8_t cc)
	{
		switch (cc)
		{
		case 0: return 4;
		case 1: return 5;
		case 2: return 6;
		case 3: return 7;
		case 4: return 0;
		case 5: return 1;
		case 6: return 2;
		case 7: return 3;
		case 8: return 12;
		case 9: return 13;
		case 10: return 14;
		case 11: return 15;
		case 12: return 8;
		case 13: return 9;
		case 14: return 10;
		case 15: return 11;
		default: return XED_ICLASS_INVALID;
		}
	}

	static xed_iclass_enum_t cc_to_movcc(uint8_t cc)
	{
		switch (cc)
		{
		case 0: return XED_ICLASS_CMOVB;
		case 1: return XED_ICLASS_CMOVBE;
		case 2: return XED_ICLASS_CMOVL;
		case 3: return XED_ICLASS_CMOVLE;
		case 4: return XED_ICLASS_CMOVNB;
		case 5: return XED_ICLASS_CMOVNBE;
		case 6: return XED_ICLASS_CMOVNL;
		case 7: return XED_ICLASS_CMOVNLE;
		case 8: return XED_ICLASS_CMOVNO;
		case 9: return XED_ICLASS_CMOVNP;
		case 10: return XED_ICLASS_CMOVNS;
		case 11: return XED_ICLASS_CMOVNZ;
		case 12: return XED_ICLASS_CMOVO;
		case 13: return XED_ICLASS_CMOVP;
		case 14: return XED_ICLASS_CMOVS;
		case 15: return XED_ICLASS_CMOVZ;
		default: return XED_ICLASS_INVALID;
		}
	}

	static xed_iclass_enum_t cc_to_jcc(uint8_t cc)
	{
		switch (cc)
		{
		case 0: return XED_ICLASS_JB;
		case 1: return XED_ICLASS_JBE;
		case 2: return XED_ICLASS_JL;
		case 3: return XED_ICLASS_JLE;
		case 4: return XED_ICLASS_JNB;
		case 5: return XED_ICLASS_JNBE;
		case 6: return XED_ICLASS_JNL;
		case 7: return XED_ICLASS_JNLE;
		case 8: return XED_ICLASS_JNO;
		case 9: return XED_ICLASS_JNP;
		case 10: return XED_ICLASS_JNS;
		case 11: return XED_ICLASS_JNZ;
		case 12: return XED_ICLASS_JO;
		case 13: return XED_ICLASS_JP;
		case 14: return XED_ICLASS_JS;
		case 15: return XED_ICLASS_JZ;
		default: return XED_ICLASS_INVALID;
		}
	}

	// This sets gadget_link and left/right adjustment
	//
	template<addr_width::type Addr_width = addr_width::x64>
	static void refresh_gadget(obf::context_t<Addr_width>& ctx, xed_condition_code_t cc)
	{
		auto& routine = ctx.additional_routines.emplace_back();
		routine.entry_link = ctx.linker.allocate_link();

		auto& block = routine.blocks.emplace_back(routine.blocks.end());
		routine.entry_block = routine.blocks.begin();

		gadget_link[cc] = ctx.linker.allocate_link();
		block.link = gadget_link[cc];
		block.termination_type = dasm::termination_type_t::returns;

		taken_adjustment[cc] = ((rand() % 100) > 50) ? rand() : -rand();
		not_taken_adjustment[cc] = ((rand() % 100) > 50) ? rand() : -rand();
		use_count[cc] = 0;

		/*block.instructions.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_simm0(not_taken_adjustment[cc], 32)
		).common_edit(ctx.linker.allocate_link(), 0, 0);*/

		block.instructions.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker.allocate_link(), 0, dasm::inst_flag::disp);
		block.instructions.back().encode_data.additional_disp = -not_taken_adjustment[cc];

		uint32_t not_taken_jump_around_link = ctx.linker.allocate_link();

		block.instructions.emplace_back(
			xed_condition_code_to_jcc(xed_invert_condition_code(cc)),
			addr_width::bits<Addr_width>::value,
			xed_relbr(0, 8)
		).common_edit(ctx.linker.allocate_link(), not_taken_jump_around_link, dasm::inst_flag::rel_br);

		/*block.instructions.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_simm0(taken_adjustment[cc], 32)
		).common_edit(ctx.linker.allocate_link(), 0, 0);*/

		block.instructions.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker.allocate_link(), 0, dasm::inst_flag::disp);
		block.instructions.back().encode_data.additional_disp = -taken_adjustment[cc];

		
		/*block.instructions.emplace_back(
			XED_ICLASS_SUB,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(not_taken_jump_around_link, 0, 0);*/
		
		block.instructions.emplace_back(
			XED_ICLASS_ADD,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(not_taken_jump_around_link, 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_POPF,
			addr_width::bits<Addr_width>::value
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_POP,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_XCHG,
			addr_width::bits<Addr_width>::value,
			xed_mem_b(max_reg_width<XED_REG_RSP, Addr_width>::value, 64),
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value)
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_RET_NEAR,
			addr_width::bits<Addr_width>::value
		).common_edit(ctx.linker.allocate_link(), 0, 0);
	}

	template<uint32_t Max_use_count = 5, addr_width::type Addr_width = addr_width::x64>
	static dasm::inst_list_t<Addr_width> gadget_entry(obf::context_t<Addr_width>& ctx, xed_condition_code_t cc, uint32_t taken_link, uint32_t not_taken_link)
	{
		if (use_count[cc] > Max_use_count)
			refresh_gadget(ctx, cc);
		++use_count[cc];


		dasm::inst_list_t<Addr_width> result;

		result.emplace_back(
			XED_ICLASS_PUSH,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value)
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_PUSH,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_PUSHF,
			addr_width::bits<Addr_width>::value
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		/*result.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker.allocate_link(), not_taken_link, dasm::inst_flag::disp);
		result.back().encode_data.additional_disp = not_taken_adjustment[cc];

		result.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker.allocate_link(), taken_link, dasm::inst_flag::disp);
		result.back().encode_data.additional_disp = taken_adjustment[cc];*/

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_simm0(0, 32)
		).common_edit(ctx.linker.allocate_link(), not_taken_link, dasm::inst_flag::rva_imm32);
		result.back().encode_data.additional_disp = not_taken_adjustment[cc];

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_simm0(0, 32)
		).common_edit(ctx.linker.allocate_link(), taken_link, dasm::inst_flag::rva_imm32);
		result.back().encode_data.additional_disp = taken_adjustment[cc];

		result.emplace_back(
			xed_condition_code_to_cmovcc(cc),
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(ctx.linker.allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_JMP,
			addr_width::bits<Addr_width>::value,
			xed_relbr(0, 32)
		).common_edit(ctx.linker.allocate_link(), gadget_link[cc], dasm::inst_flag::rel_br | dasm::inst_flag::block_terminator);

		return result;
	}

	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{
		if (!first_gadgets_setup)
		{
			for (uint8_t i = 0; i < XED_CC_COMPAT_END; ++i)
				refresh_gadget(ctx, static_cast<xed_condition_code_t>(i));
			first_gadgets_setup = true;
		}

		for (auto& block : routine.blocks)
		{
			switch (block.termination_type)
			{
			case dasm::termination_type_t::unconditional_br:
				block.instructions.splice(
					block.instructions.end(),
					gadget_entry<15>(
						ctx,
						static_cast<xed_condition_code_t>(rand() % XED_CC_COMPAT_END),
						block.taken_block->link,
						block.taken_block->link
					)
				);
				break;
			case dasm::termination_type_t::conditional_br:
			{
				auto jcc = std::prev(block.instructions.end());
				auto cc = xed_iclass_to_condition_code(xed_decoded_inst_get_iclass(&jcc->decoded_inst));
				if (cc < XED_CC_COMPAT_END)
				{
					block.instructions.splice(
						jcc,
						gadget_entry<15>(
							ctx,
							cc,
							block.taken_block->link,
							block.fallthrough_block->link
							)
					);
					// pop the jcc
					//
					block.instructions.pop_back();
				}
				break;
			}
			case dasm::termination_type_t::fallthrough:
				block.instructions.splice(
					block.instructions.end(),
					gadget_entry<15>(
						ctx,
						static_cast<xed_condition_code_t>(rand() % XED_CC_COMPAT_END),
						block.fallthrough_block->link,
						block.fallthrough_block->link
					)
				);
				break;
			}
		}

		return obf::pass_status_t::success;
	}
};


