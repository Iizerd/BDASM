#pragma once

#include "obf.h"

// These are all the passes that play around with the original memory of the function
//

// It's required that this pass be run before any that might alter the start and end rvas set in the 
// disassembly process
//
struct pad_original_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{
		for (auto& block : routine.blocks)
		{
			memset(ctx.bin.mapped_image + block.rva_start, 0xCC, block.rva_end - block.rva_start);
		}

		return obf::pass_status_t::success;
	}
};

// Add one here that obfuscates the jumps
//