#pragma once

#include "obf_structures.h"
#include "encoder.h"

// write func to perform complete stack analysis with blocks that have references to the other blocks blah blah blah
// use iterators for the references
//
namespace obf
{
	struct stack_allocation_t
	{
		template<addr_width::type Addr_width = addr_width::x64>
		struct my_context_t
		{
			context_t<Addr_width>& ctx;

			// The visited value to check for when visiting a block
			//
			uint32_t visited;

			// Size of the original allocation. Zero for funcs that did not allocate
			//
			int32_t original_alloc;

			// Size we need to edit allocator/deallocator by
			//
			int32_t additional_alloc;

			// bp based memory access also needs to be adjusted
			//
			bool bp_based;

			// No calls or jumps to undetermined locations
			//
			bool custom_alloc_possible;

			my_context_t(context_t<Addr_width>& context, uint32_t vis, int32_t alloc_size)
				: ctx(context)
				, visited(vis)
				, original_alloc(0)
				, additional_alloc(alloc_size)
				, bp_based(false)
				, custom_alloc_possible(true)
			{}
		};

		// returns true if the function is a candidate for a custom allocation
		// No calls or undetermined jumps
		//
		template<addr_width::type Addr_width = addr_width::x64>
		static void run_stack_analysis(my_context_t<Addr_width>& ctx, dasm::routine_t<Addr_width>& routine)
		{
			for (auto block_it_t = routine.blocks.begin(); block_it_t != routine.blocks.end(); ++block_it_t)
			{
				for (auto inst_it = block_it_t->instructions.begin(); inst_it != block_it_t->instructions.end(); ++inst_it)
				{
					auto iform = xed_decoded_inst_get_iform_enum(&inst_it->decoded_inst);
					if (iform == XED_IFORM_SUB_GPRv_IMMz || iform == XED_IFORM_SUB_GPRv_IMMb &&
						get_max_reg_size<XED_REG_RSP, Addr_width>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
					{
						ctx.original_alloc = xed_decoded_inst_get_signed_immediate(&inst_it->decoded_inst);
					}
					else if ((iform == XED_IFORM_MOV_GPRv_GPRv_89 || iform == XED_IFORM_MOV_GPRv_GPRv_8B) &&
						get_max_reg_size<XED_REG_RBP, Addr_width>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0) &&
						get_max_reg_size<XED_REG_RSP, Addr_width>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG1))
					{
						ctx.bp_based = true;
					}
					else if (auto icat = xed_decoded_inst_get_category(&inst_it->decoded_inst);
						icat == XED_CATEGORY_CALL)
					{
						ctx.custom_alloc_possible = false;
					}
				}

				if (block_it_t->termination_type == dasm::termination_type_t::undetermined_unconditional_br)
					ctx.custom_alloc_possible = false;
			}
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static void recursive_disp_fixup(dasm::block_it_t<Addr_width> block, my_context_t<Addr_width>& ctx, bool in_allocation)
		{
			// Dont continue because we have already touched this block
			//
			if (block->visited == ctx.visited)
				return;

			for (auto inst_it = block->instructions.begin(); inst_it != block->instructions.end(); ++inst_it)
			{
				auto iform = xed_decoded_inst_get_iform_enum(&inst_it->decoded_inst);
				if (iform == XED_IFORM_SUB_GPRv_IMMz || iform == XED_IFORM_SUB_GPRv_IMMb &&
					get_max_reg_size<XED_REG_RSP, Addr_width>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
				{
					//printf("Found allocator. %X\n", ctx.original_alloc + ctx.additional_alloc);
					xed_decoded_inst_set_immediate_signed_bits(&inst_it->decoded_inst, ctx.original_alloc + ctx.additional_alloc, 32);
					in_allocation = true;
				}
				else if (iform == XED_IFORM_ADD_GPRv_IMMz || XED_IFORM_ADD_GPRv_IMMb &&
					get_max_reg_size<XED_REG_RSP, Addr_width>::value == xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0))
				{
					//printf("Found deallocator. %X\n", ctx.original_alloc + ctx.additional_alloc);

					xed_decoded_inst_set_immediate_signed_bits(&inst_it->decoded_inst, ctx.original_alloc + ctx.additional_alloc, 32);
					in_allocation = false;
				}
				else if (in_allocation)
				{
					auto inst = xed_decoded_inst_inst(&inst_it->decoded_inst);
					auto num_operands = xed_decoded_inst_noperands(&inst_it->decoded_inst);

					for (uint32_t i = 0; i < num_operands; ++i)
					{
						auto operand = xed_inst_operand(inst, i);
						auto operand_name = xed_operand_name(operand);
						if (operand_name == XED_OPERAND_MEM0 || operand_name == XED_OPERAND_AGEN)
						{
							//printf("found one to patch. %X\n", inst_it->original_rva);
							if (get_max_reg_size<XED_REG_RSP, Addr_width>::value ==
								xed_decoded_inst_get_base_reg(&inst_it->decoded_inst, 0))
							{
								auto disp = xed_decoded_inst_get_memory_displacement(&inst_it->decoded_inst, 0);
								// If our disp is less than the allocation size, we are accessing data in the allocation
								// Otherwise we are accessing data in args, home space, or return addr
								//
								if (disp > ctx.original_alloc)
								{
									xed_decoded_inst_set_memory_displacement(&inst_it->decoded_inst, disp + ctx.additional_alloc, 4);
								}
							}
							else if (ctx.bp_based &&
								get_max_reg_size<XED_REG_RBP, Addr_width>::value ==
								xed_decoded_inst_get_base_reg(&inst_it->decoded_inst, 0))
							{
								auto disp = xed_decoded_inst_get_memory_displacement(&inst_it->decoded_inst, 0);
								// If our displacement is less than 0 we are accessing allocated space
								// otherwise ''
								//
								if (disp < 0)
								{
									xed_decoded_inst_set_memory_displacement_bits(&inst_it->decoded_inst, disp - ctx.additional_alloc, 32);
								}
							}
						}
					}
				}
			}

			++block->visited;
			block->invoke_for_next(recursive_disp_fixup<Addr_width>, ctx, in_allocation);
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static void insert_deallocators(dasm::block_it_t<Addr_width> block, my_context_t<Addr_width>& ctx)
		{
			if (block->visited == ctx.visited)
				return;

			if (block->termination_type == dasm::termination_type_t::returns ||
				block->termination_type == dasm::termination_type_t::undetermined_unconditional_br)
			{
				// Allocate and place the deallocator before the last terminating instruction
				//
				uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
				block->instructions.emplace(std::prev(block->instructions.end()))->decode(
					buffer,
					encode_inst_in_place(
						buffer,
						addr_width::machine_state<Addr_width>::value,
						XED_ICLASS_ADD,
						addr_width::bits<Addr_width>::value,
						xed_reg(get_max_reg_size<XED_REG_RSP, Addr_width>::value),
						xed_simm0(
							ctx.additional_alloc,
							32
						)
					)
				);
			}

			++block->visited;
			block->invoke_for_next(insert_deallocators<Addr_width>, ctx);
		}


		// Puts the rsp offset where our data starts into allocation_size
		//
		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx, int32_t& allocation_size)
		{
			routine.reset_visited();
			my_context_t<Addr_width> my_ctx = { ctx, 1, allocation_size };

			run_stack_analysis(my_ctx, routine);
			
			// If there wasnt any stack allocation originally, we insert one if possible
			//
			if (!my_ctx.original_alloc)
			{
				if (my_ctx.custom_alloc_possible)
				{
					// Create custom stack allocators
					//
					uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

					routine.entry_block->instructions.emplace_front().decode(
						buffer,
						encode_inst_in_place(
							buffer,
							addr_width::machine_state<Addr_width>::value,
							XED_ICLASS_SUB,
							addr_width::bits<Addr_width>::value,
							xed_reg(get_max_reg_size<XED_REG_RSP, Addr_width>::value),
							xed_simm0(
								allocation_size, 
								32
							)
						)
					);
					routine.entry_block->instructions.front().my_link = ctx.linker->allocate_link();

					insert_deallocators(routine.entry_block, my_ctx);
					routine.reset_visited();
				}
				else
					return pass_status_t::failure;
			}

			recursive_disp_fixup(routine.entry_block, my_ctx, false);
			return pass_status_t::success;
		}
	};
}