#pragma once

#include "dasm.h"

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
	template<addr_width::type Addr_width = addr_width::x64>
	class substitution_t
	{

	};
}