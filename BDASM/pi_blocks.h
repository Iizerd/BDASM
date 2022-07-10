#pragma once

#include "obf_structures.h"

#include "encoder.h"

// Make all blocks of a routine position independent inside the binary by appending
// an absolute jump onto the end of blocks that feature a fallthrough.
//

namespace obf
{
	template<addr_width::type Addr_width = addr_width::x64>
	class position_independent_blocks_t
	{
		static pass_status_t pass(context_t<Addr_width>& ctx, dasm::routine_t<Addr_width>& routine)
		{
			for (auto& block : routine.blocks)
			{
				switch (block.termination_type)
				{
				case dasm::block_t<>::termination_type_t::invalid:
					return pass_status_t::critical_failure;
				case dasm::block_t<>::termination_type_t::returns:
				case dasm::block_t<>::termination_type_t::unconditional_br:
					break;

					// These two termination types have fallthroughs and need to have an absolute 
					// jump patched onto the end to make them position independent.
					//
				case dasm::block_t<>::termination_type_t::conditional_br: [[fallthrough]];
				case dasm::block_t<>::termination_type_t::fallthrough:

					uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

					block.instructions.emplace_back().decode(buffer, encode_inst_in_place(buffer,
						addr_width::machine_state<Addr_width>::value,
						XED_ICLASS_JMP,
						addr_width::bits<Addr_width>::value,
						xed_relbr(0, 32)
					));
					block.instructions.back().my_link = ctx->linker->allocate_link();
					block.instructions.back().used_link = block.fallthrough_block->link;
					block.instructions.back().original_rva = 0;

					break;
				case dasm::block_t<>::termination_type_t::undetermined_unconditional_br:
					break;
				default:
					return pass_status_t::critical_failure;
				}
			}
			return pass_status_t::success;
		}
	};
}