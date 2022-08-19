#pragma once

#include "obf.h"
#include "encoder.h"

// The goal of this is to substitute instructions with other harder to understand 
// instruction combinations. Very similar to MBA but i thought it deserved its own
// pass because its not really related to math. See as follows
// 
// MOV A,B
//	OR A,B
//  AND A,B
//	
//

namespace obf
{
	struct substitution_t
	{
		template<addr_width::type aw = addr_width::x64>
		static bool pass(dasm::routine_t<aw>& routine, context_t<aw>& ctx, uint32_t percent_chance, uint32_t min_count, bool red_space_store = false)
		{

		}
	};
}