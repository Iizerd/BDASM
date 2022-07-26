#pragma once

#include "obf.h"
#include "encoder.h"

// Make all blocks of a routine position independent inside the binary by appending
// an absolute jump onto the end of blocks that feature a fallthrough.
//

struct position_independent_blocks_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{
		for (auto& block : routine.blocks)
		{
			switch (block.termination_type)
			{
			case dasm::termination_type_t::invalid:
				std::printf("Invalid block termination type in block [%08X:%08X]\n", block.rva_start, block.rva_end);
				return obf::pass_status_t::critical_failure;
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
				).common_edit(ctx.linker.allocate_link(), block.fallthrough_block->link, dasm::inst_flag::rel_br | dasm::inst_flag::block_terminator);
				block.instructions.back().original_rva = 0;

				break;
			case dasm::termination_type_t::undetermined_unconditional_br:
				break;
			default:
				std::printf("Unknown block termination type.\n");
				return obf::pass_status_t::critical_failure;
			}
		}
		return obf::pass_status_t::success;
	}
};