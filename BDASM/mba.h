#pragma once

/*
	A + B | ~A - ~B

	~A | A ^ ~0
*/

#include "obf_structures.h"

namespace obf
{
	template<addr_width::type Addr_width = addr_width::x64>
	class mba_t
	{
		static bool pass(context_t<Addr_width>& ctx, dasm::routine_t<Addr_width>& routine)
		{

		}
	};
}

