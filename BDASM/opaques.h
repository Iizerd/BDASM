#pragma once


#include "obf_structures.h"


// Locate places where we know the state of certain flags, then jump based on them
// Example1: trace forward the flag used by a jcc, find where its written to again, and right before then place an opaque
// Example2: find places where constant values are moved into registers, trace forward until they are potentially invalidated and
//		place an opaque right before
// 
// 
// 

namespace obf
{
	// Trace flags after a previous conditional jump until it is written to, then insert a branch before that
	// using the known flag value
	//
	struct opaque_from_flags_t
	{
		// This splits an existing block, creating a fallthrough, and returning the link for the newly created block
		//
		template<addr_width::type Addr_width = addr_width::x64>
		static uint32_t split_random_block(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx)
		{

			auto block_it = routine.blocks.begin();
			uint32_t max_count = routine.blocks.size() * 2;
			while (block_it->instructions.size() < 2)
			{
				std::advance(block_it, rand() % routine.blocks.size());
				if (--max_count == 0)
					return dasm::linker_t::invalid_link_value;
			}

			auto inst_it = block_it->instructions.begin();
			std::advance(inst_it, rand() % block_it->instructions.size() - 1); //-1 so we not at the end namean man?

			auto& new_block = routine.blocks.emplace_front(routine.blocks.end());

			// Setup new block
			//
			new_block.link = ctx.linker->allocate_link();
			new_block.rva_start = inst_it->original_rva;
			new_block.rva_end = block_it->rva_end;
			new_block.termination_type = block_it->termination_type;
			new_block.taken_block = block_it->taken_block;
			new_block.fallthrough_block = block_it->fallthrough_block;
			new_block.instructions.splice(new_block.instructions.end(), block_it->instructions, inst_it, block_it->instructions.end());

			// Set old blocks termination_type to fallthrough
			//
			block_it->termination_type = dasm::termination_type_t::fallthrough;
			block_it->fallthrough_block = routine.blocks.begin();
			block_it->taken_block = routine.blocks.end();
			block_it->rva_end = inst_it->original_rva;


		}


		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx)
		{
			for (auto block_it = routine.blocks.begin(); block_it != routine.blocks.end(); ++block_it)
			{
				for (auto inst_it = block_it->instructions.begin(); inst_it != routine.blocks.end(); ++inst_it)
				{

				}
				auto cat = xed_decoded_inst_get_category()
			}
			//split_random_block(routine, ctx);
			//return pass_status_t::success;
		}
	};

	struct opaque_from_const_t
	{
		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx)
		{

		}
	};

	struct opaque_code_copy_t
	{
		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx)
		{

		}
	};
}