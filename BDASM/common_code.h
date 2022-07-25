#pragma once

#include "obf.h"

// So, a lot of code is repeated in binaries. So the idea is ill put these common blocks of code that 
// all routines can jump to. Like vm handlers :)
// 
// [IMPORTANT] You access these blocks by transfering control flow with a call, then its returned to you 
// with a ret. this however moves the stack by 8(or 4) bytes so this must be accounted for. All [rsp] 
// displacements must be adjusted, [rbp] does not need this however.
//
// The most obvious example of this can be applied in function prologues. Specifically around stack
// allocations and home space storage.
//

struct common_prologue_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{

	}
};

struct common_epilogue_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{

	}
};

struct common_code_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{

	}
};

