#pragma once

#include "obf.h"
#include "encoder.h"
#include "backtrace.h"

// I can actually handle the special stack deallocators... i just need to trace back to where the reg moved into rsp is used
// see if its a lea reg,[rsp+stack_allocation] then adjust accordingly.
//

// write func to perform complete stack analysis with blocks that have references to the other blocks blah blah blah
// use iterators for the references
//
struct stack_allocation_t
{
	template<addr_width::type aw = addr_width::x64>
	struct my_context_t
	{
		obf::obf_t<aw>& ctx;

		// The visited value to check for when visiting a block
		//
		uint32_t visited;

		// Size we need to edit allocator/deallocator by
		//
		int32_t additional_alloc;

		// Size of the original allocation. Zero for funcs that did not allocate
		//
		int32_t sp_allocation;

		// How far into new memory bp is, because it could be different from sp
		//
		int32_t bp_allocation;

		// Bp based memory access also needs to be adjusted
		//
		bool bp_based;

		// This is when this happens
		//
		//	lea rbp,[rsp+-const]
		//	sub rsp,const
		bool lea_to_bp;

		bool custom_alloc_possible;

		my_context_t(obf::obf_t<aw>& context, uint32_t vis, int32_t alloc_size)
			: ctx(context)
			, visited(vis)
			, additional_alloc(alloc_size)
			, sp_allocation(0)
			, bp_allocation(0)
			, bp_based(false)
			, lea_to_bp(false)
			, custom_alloc_possible(true)
		{}
	};

	// Sometimes msvc decides to randomly move rsp into rax or some other reg, this will tracebackwards from a lea 
	// searching for a 'mov rax,rsp' to see if that is the case
	//
	template<addr_width::type aw = addr_width::x64>
	static bool does_reg_equal_sp(xed_reg_enum_t reg, dasm::block_it_t<aw> block, dasm::inst_it_t<aw> inst)
	{
		if (reg == max_reg_width<XED_REG_RSP, aw>::value)
			return true;

		// Otherwise, we trace backwards in the current block looking for a place where 'reg' might be set to sp
		//
		for (auto rev = std::make_reverse_iterator(inst); rev != block->instructions.rend(); ++rev)
		{
			if (auto iform = rev->iform();
				(iform == XED_IFORM_MOV_GPRv_GPRv_89 || iform == XED_IFORM_MOV_GPRv_GPRv_8B) &&
				reg == xed_decoded_inst_get_reg(&rev->decoded_inst, XED_OPERAND_REG0) &&
				max_reg_width<XED_REG_RSP, aw>::value == xed_decoded_inst_get_reg(&rev->decoded_inst, XED_OPERAND_REG1))
			{
				return true;
			}

			// We will check all operands of the instruction to see if this reg we are looking at is clobbered
			// if it is and we havnt found that sp was moved into it yet, then it couldnt possibly equal sp at
			// the place we need it to.
			//
			auto inst = rev->inst();
			auto num_operands = rev->noperands();

			for (uint32_t i = 0; i < num_operands; ++i)
			{
				auto operand = xed_inst_operand(inst, i);
				if (xed_operand_written(operand))
				{
					auto operand_name = xed_operand_name(operand);
					if (xed_operand_is_register(operand_name))
					{
						if (reg == xed_decoded_inst_get_reg(&rev->decoded_inst, operand_name))
							return false;
					}
				}
			}
		}

		return false;
	}

	// returns true if the function is a candidate for a custom allocation
	// No calls or undetermined jumps
	//
	template<addr_width::type aw = addr_width::x64>
	static bool run_stack_analysis(my_context_t<aw>& ctx, dasm::routine_t<aw>& routine)
	{
		for (auto block_it = routine.blocks.begin(); block_it != routine.blocks.end(); ++block_it)
		{
			bool found_standard_deallocator = false;
			for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end(); ++inst_it)
			{
				auto iform = inst_it->iform();
				if (iform == XED_IFORM_SUB_GPRv_IMMz || iform == XED_IFORM_SUB_GPRv_IMMb &&
					max_reg_width<XED_REG_RSP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
				{
					if (ctx.sp_allocation)
						return false;
					ctx.sp_allocation = xed_decoded_inst_get_signed_immediate(&inst_it->decoded_inst);
				}
				if (iform == XED_IFORM_ADD_GPRv_IMMz || iform == XED_IFORM_ADD_GPRv_IMMb &&
					max_reg_width<XED_REG_RSP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
				{
					found_standard_deallocator = true;
				}
				else if ((iform == XED_IFORM_MOV_GPRv_GPRv_89 || iform == XED_IFORM_MOV_GPRv_GPRv_8B) &&
					max_reg_width<XED_REG_RBP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0) &&
					max_reg_width<XED_REG_RSP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG1))
				{
					ctx.bp_based = true;
					ctx.lea_to_bp = false;
					ctx.bp_allocation = ctx.sp_allocation;
					//printf("------MOV BP. %X\n", inst_it->original_rva);
				}
				else if ((iform == XED_IFORM_LEA_GPRv_AGEN) && 
					max_reg_width<XED_REG_RBP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0) &&
					does_reg_equal_sp(xed_decoded_inst_get_base_reg(&inst_it->decoded_inst, 0), block_it, inst_it))
				{
					// If bp gets moved around a lot then we cant reliably track it with this
					//
					if (ctx.bp_based)
						return false;

					ctx.bp_based = true;
					ctx.lea_to_bp = true;
					ctx.bp_allocation = (-xed_decoded_inst_get_memory_displacement(&inst_it->decoded_inst, 0)) + ctx.sp_allocation;
					//printf("-----LEA BP. %X\n", inst_it->original_rva);
				}
				else if (auto icat = xed_decoded_inst_get_category(&inst_it->decoded_inst);
					icat == XED_CATEGORY_CALL)
				{
					ctx.custom_alloc_possible = false;
				}
			}

			if (block_it->termination_type == dasm::termination_type_t::undetermined_unconditional_br)
				ctx.custom_alloc_possible = false;

			if (block_it->termination_type == dasm::termination_type_t::returns && found_standard_deallocator == false)
				return false;
		}
		return true;
	}

	template<addr_width::type aw = addr_width::x64>
	static void recursive_disp_fixup(dasm::block_it_t<aw> block, my_context_t<aw>& ctx, bool in_allocation)
	{
		// Dont continue because we have already touched this block
		//
		if (block->visited == ctx.visited)
			return;

		for (auto inst_it = block->instructions.begin(); inst_it != block->instructions.end(); ++inst_it)
		{
			auto iform = inst_it->iform();
			if (iform == XED_IFORM_SUB_GPRv_IMMz || iform == XED_IFORM_SUB_GPRv_IMMb &&
				max_reg_width<XED_REG_RSP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
			{
				//printf("Found allocator. %X\n", ctx.sp_allocation + ctx.additional_alloc);
				xed_decoded_inst_set_immediate_signed_bits(&inst_it->decoded_inst, ctx.sp_allocation + ctx.additional_alloc, 32);
				in_allocation = true;
			}
			else if (iform == XED_IFORM_ADD_GPRv_IMMz || XED_IFORM_ADD_GPRv_IMMb &&
				max_reg_width<XED_REG_RSP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
			{
				//printf("Found deallocator. %X\n", ctx.sp_allocation + ctx.additional_alloc);

				xed_decoded_inst_set_immediate_signed_bits(&inst_it->decoded_inst, ctx.sp_allocation + ctx.additional_alloc, 32);
				in_allocation = false;
			}
			else if (ctx.bp_based && iform == XED_IFORM_LEA_GPRv_AGEN && 
				max_reg_width<XED_REG_RBP, aw>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0) &&
				does_reg_equal_sp(xed_decoded_inst_get_base_reg(&inst_it->decoded_inst, 0), block, inst_it))
			{
				//printf("found lea to do allocation on %X\n", inst_it->original_rva);
				auto disp = xed_decoded_inst_get_memory_displacement(&inst_it->decoded_inst, 0);
				xed_decoded_inst_set_memory_displacement_bits(&inst_it->decoded_inst, disp - ctx.additional_alloc, 32);
				inst_it->redecode();
			}
			else if (in_allocation)
			{
				auto inst = inst_it->inst();
				auto num_operands = inst_it->noperands();

				for (uint32_t i = 0; i < num_operands; ++i)
				{
					auto operand = xed_inst_operand(inst, i);
					auto operand_name = xed_operand_name(operand);
					if (operand_name == XED_OPERAND_MEM0 || operand_name == XED_OPERAND_AGEN)
					{
						//printf("found one to patch. %X\n", inst_it->original_rva);
						if (max_reg_width<XED_REG_RSP, aw>::value ==
							xed_decoded_inst_get_base_reg(&inst_it->decoded_inst, 0))
						{
							auto disp = xed_decoded_inst_get_memory_displacement(&inst_it->decoded_inst, 0);
							// If our disp is less than the allocation size, we are accessing data in the allocation
							// Otherwise we are accessing data in args, home space, or return addr
							//
							if (disp > ctx.sp_allocation)
							{
								xed_decoded_inst_set_memory_displacement(&inst_it->decoded_inst, disp + ctx.additional_alloc, 4);
							}
							inst_it->redecode();
						}
						else if (ctx.bp_based &&
							max_reg_width<XED_REG_RBP, aw>::value ==
							xed_decoded_inst_get_base_reg(&inst_it->decoded_inst, 0))
						{
							auto disp = xed_decoded_inst_get_memory_displacement(&inst_it->decoded_inst, 0);

							// This logic needs to get checked...
							//
							if (ctx.bp_allocation != 0 && disp >= ctx.bp_allocation)
							{
								xed_decoded_inst_set_memory_displacement_bits(&inst_it->decoded_inst, disp + ctx.additional_alloc, 32);
							}
							else if (ctx.bp_allocation == 0 && disp < 0)
							{
								xed_decoded_inst_set_memory_displacement_bits(&inst_it->decoded_inst, disp - ctx.additional_alloc, 32);
							}
							inst_it->redecode();
						}
					}
				}
			}
		}

		++block->visited;
		block->invoke_for_next(recursive_disp_fixup<aw>, ctx, in_allocation);
	}

	template<addr_width::type aw = addr_width::x64>
	static void insert_deallocators(dasm::block_it_t<aw> block, my_context_t<aw>& ctx)
	{
		if (block->visited == ctx.visited)
			return;

		if (block->termination_type == dasm::termination_type_t::returns ||
			block->termination_type == dasm::termination_type_t::undetermined_unconditional_br)
		{
			// Allocate and place the deallocator before the last terminating instruction
			//
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
			block->instructions.emplace(std::prev(block->instructions.end()),
				XED_ICLASS_ADD,
				addr_width::bits<aw>::value,
				xed_reg(max_reg_width<XED_REG_RSP, aw>::value),
				xed_simm0(
					ctx.additional_alloc,
					32
				)
			)->common_edit(ctx.ctx.linker->allocate_link(), 0, 0);
		}

		++block->visited;
		block->invoke_for_next(insert_deallocators<aw>, ctx);
	}


	// Puts the rsp offset where our data starts into allocation_size
	//
	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<aw>& routine, obf::obf_t<aw>& ctx, int32_t& allocation_size)
	{
		/*if (routine.entry_block->rva_start >= 0x1B71)
			return obf::pass_status_t::failure;*/

		routine.reset_visited();
		my_context_t<aw> my_ctx = { ctx, 1, allocation_size };

		if (!run_stack_analysis(my_ctx, routine))
			return obf::pass_status_t::failure;

		// If there wasnt any stack allocation originally, we insert one if possible
		//
		if (!my_ctx.sp_allocation)
		{
			return obf::pass_status_t::failure;

			if (my_ctx.custom_alloc_possible)
			{
				// Create custom stack allocators
				//
				uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

				routine.entry_block->instructions.emplace_front(
					XED_ICLASS_SUB,
					addr_width::bits<aw>::value,
					xed_reg(max_reg_width<XED_REG_RSP, aw>::value),
					xed_simm0(
						allocation_size,
						32
					)
				).common_edit(ctx.linker->allocate_link(), 0, 0);

				insert_deallocators(routine.entry_block, my_ctx);
				routine.reset_visited();
			}
			else
				return obf::pass_status_t::failure;
		}

		//if (my_ctx.bp_based)
		//	return obf::pass_status_t::failure;
		
		recursive_disp_fixup(routine.entry_block, my_ctx, false);
		return obf::pass_status_t::success;
	}
};