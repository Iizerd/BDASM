#pragma once

#include "obf.h"
#include "flags.h"

struct constant_encryption_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::obf_t<Addr_width>& ctx)
	{
		for (auto& block : routine.blocks)
		{
			for (auto inst = block.instructions.begin(); inst != block.instructions.end(); ++inst)
			{

			}

		}
	}
};