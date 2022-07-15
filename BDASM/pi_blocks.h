#pragma once

#include "obf_structures.h"
#include "encoder.h"

// Make all blocks of a routine position independent inside the binary by appending
// an absolute jump onto the end of blocks that feature a fallthrough.
//

namespace obf
{
	struct position_independent_blocks_t
	{
		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx)
		{
			for (auto& block : routine.blocks)
			{
				switch (block.termination_type)
				{
				case dasm::termination_type_t::invalid:
					return pass_status_t::critical_failure;
				case dasm::termination_type_t::returns:
				case dasm::termination_type_t::unconditional_br:
					break;

					// These two termination types have fallthroughs and need to have an absolute 
					// jump patched onto the end to make them position independent.
					//
				case dasm::termination_type_t::conditional_br: [[fallthrough]];
				case dasm::termination_type_t::fallthrough:

					uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

					block.instructions.emplace_back(
						XED_ICLASS_JMP,
							32,
							xed_relbr(0, 32)
					).common_edit(ctx.linker->allocate_link(), block.fallthrough_block->link, dasm::inst_flag::rel_br | dasm::inst_flag::block_terminator);
					block.instructions.back().original_rva = 0;

					break;
				case dasm::termination_type_t::undetermined_unconditional_br:
					break;
				default:
					return pass_status_t::critical_failure;
				}
			}
			return pass_status_t::success;
		}
	};
}