#pragma once

#include "addr_width.h"
#include "inst.h"

namespace obf
{
	namespace gen
	{
		constexpr uint32_t max_nop_size = 9;
		template<address_width Addr_width = address_width::x64>
		inline inst_list_t<Addr_width> nops(uint32_t length)
		{
			inst_list_t<Addr_width> result;
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
			uint32_t fulls = length / max_nop_size;
			uint32_t single = length % max_nop_size;
			for (uint32_t i = 0; i < fulls; ++i)
			{
				xed_encode_nop(buffer, max_nop_size);
				result.emplace_back().decode(buffer, XED_MAX_INSTRUCTION_BYTES);
			}
			if (single)
			{
				xed_encode_nop(buffer, single);
				result.emplace_back().decode(buffer, XED_MAX_INSTRUCTION_BYTES);
			}

			return result;
		}
	}
}







