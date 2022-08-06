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

	// This sets gadget_link and left/right adjustment
	//
	template<addr_width::type Addr_width = addr_width::x64>
	static void refresh_gadget(obf::obf_t<Addr_width>& ctx, xed_condition_code_t cc)
	{
		auto& routine = ctx.additional_routines.emplace_back();
		routine.entry_link = ctx.linker->allocate_link();

		auto& block = routine.blocks.emplace_back(routine.blocks.end());
		routine.entry_block = routine.blocks.begin();

		gadget_link[cc] = ctx.linker->allocate_link();
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
		).common_edit(ctx.linker->allocate_link(), 0, 0);*/

		block.instructions.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, dasm::inst_flag::disp);
		block.instructions.back().encode_data.additional_disp = -not_taken_adjustment[cc];

		uint32_t not_taken_jump_around_link = ctx.linker->allocate_link();

		block.instructions.emplace_back(
			xed_condition_code_to_jcc(xed_invert_condition_code(cc)),
			addr_width::bits<Addr_width>::value,
			xed_relbr(0, 8)
		).common_edit(ctx.linker->allocate_link(), not_taken_jump_around_link, dasm::inst_flag::rel_br);

		/*block.instructions.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_simm0(taken_adjustment[cc], 32)
		).common_edit(ctx.linker->allocate_link(), 0, 0);*/

		block.instructions.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker->allocate_link(), 0, dasm::inst_flag::disp);
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
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_POP,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_XCHG,
			addr_width::bits<Addr_width>::value,
			xed_mem_b(max_reg_width<XED_REG_RSP, Addr_width>::value, 64),
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		block.instructions.emplace_back(
			XED_ICLASS_RET_NEAR,
			addr_width::bits<Addr_width>::value
		).common_edit(ctx.linker->allocate_link(), 0, 0);
	}

	template<uint32_t Max_use_count = 5, addr_width::type Addr_width = addr_width::x64>
	static dasm::inst_list_t<Addr_width> gadget_entry(obf::obf_t<Addr_width>& ctx, xed_condition_code_t cc, uint32_t taken_link, uint32_t not_taken_link)
	{
		if (use_count[cc] > Max_use_count)
			refresh_gadget(ctx, cc);
		++use_count[cc];


		dasm::inst_list_t<Addr_width> result;

		result.emplace_back(
			XED_ICLASS_PUSH,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_PUSH,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_PUSHF,
			addr_width::bits<Addr_width>::value
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		/*result.emplace_back(
			XED_ICLASS_LEA,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_mem_bd(
				max_reg_width<XED_REG_RIP, Addr_width>::value,
				xed_disp(0, 32),
				addr_width::bits<Addr_width>::value
			)
		).common_edit(ctx.linker->allocate_link(), not_taken_link, dasm::inst_flag::disp);
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
		).common_edit(ctx.linker->allocate_link(), taken_link, dasm::inst_flag::disp);
		result.back().encode_data.additional_disp = taken_adjustment[cc];*/

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_simm0(0, 32)
		).common_edit(ctx.linker->allocate_link(), not_taken_link, dasm::inst_flag::rva_imm32);
		result.back().encode_data.additional_disp = not_taken_adjustment[cc];

		result.emplace_back(
			XED_ICLASS_MOV,
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value),
			xed_simm0(0, 32)
		).common_edit(ctx.linker->allocate_link(), taken_link, dasm::inst_flag::rva_imm32);
		result.back().encode_data.additional_disp = taken_adjustment[cc];

		result.emplace_back(
			xed_condition_code_to_cmovcc(cc),
			addr_width::bits<Addr_width>::value,
			xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
			xed_reg(max_reg_width<XED_REG_RBX, Addr_width>::value)
		).common_edit(ctx.linker->allocate_link(), 0, 0);

		result.emplace_back(
			XED_ICLASS_JMP,
			addr_width::bits<Addr_width>::value,
			xed_relbr(0, 32)
		).common_edit(ctx.linker->allocate_link(), gadget_link[cc], dasm::inst_flag::rel_br | dasm::inst_flag::block_terminator);

		return result;
	}

	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::obf_t<Addr_width>& ctx)
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


