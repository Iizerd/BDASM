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
	template<addr_width::type Addr_width = addr_width::x64>
	struct opaque_predicates_t
	{
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx, )
		{

		}
	};
}