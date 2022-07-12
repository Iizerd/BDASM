#pragma once

/*
	ADD:
		A + B == ~A - ~B

	SUB:
		A - B == ~A + ~B

	OR:
		
	NOT:
		~A == A ^ ~0
*/

#include "obf_structures.h"

namespace obf
{
	template<addr_width::type Addr_width = addr_width::x64>
	struct mba_t
	{
		enum class mba_type_t
		{
			_add,
			_sub,
			_not,
			_and,
			_or,
			_xor,
		};


		static dasm::inst_list_t<Addr_width> add_1(dasm::inst_it_t<Addr_width> inst)
		{

		}

		static uint32_t count_candidate_instructions(dasm::routine_t<Addr_width>& routine)
		{
			uint32_t count = 0;
			for (auto block_it = routine.blocks.begin(); block_it != routine.blocks.end(); ++block_it)
			{
				for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end(); ++inst_it)
				{
					switch (xed_decoded_inst_get_iclass(&inst_it->decoded_inst))
					{
					case XED_ICLASS_ADD: [[fallthrough]];
					case XED_ICLASS_SUB: [[fallthrough]];
					case XED_ICLASS_NOT: [[fallthrough]];
					case XED_ICLASS_AND: [[fallthrough]];
					case XED_ICLASS_OR: [[fallthrough]];
					case XED_ICLASS_XOR:
						count++;
					}
				}
			}
		}
		// percent_chance: 0-100 chance to mutate a possible inst
		// min_count: minimum number of instructions to mutate
		// red_space_store: store variables in unallocated stack memory
		//
		static bool pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx, uint32_t percent_chance, uint32_t min_count, bool red_space_store = false)
		{

		}
	};
}

