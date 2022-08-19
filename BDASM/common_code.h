#pragma once

#include "obf.h"

#include "dpattern.h"
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

struct common_stack_manip_t
{
	// Inserts a function that does this
	//	Assumes rax is caller saved
	//  Ex: 
	//		push stack_adjustment	; +8
	//		call stack_manipulator	; +8-8
	//  
	// 
	//	stack_manipulator proc
	//		xchg rax,[rsp+8h]		; swap rax and stack adjustment 
	//		xchg rbx,[rsp]
	//		sub rsp,rax				; +stack_adjustment
	//		mov [rsp+8h],rbx		; [rsp+8] is return address
	//		mov rbx,[rsp+rax]		; restore the original rbx value
	//		mov rax,[rsp+rax+8h]
	//		add rsp,8h				; take care of the 8 bytes from pushed stack_adjustment value
	//		ret						; pops [rsp]
	//  stack_manipulator endp
	//
	//		//xchg rbx,[rsp+rax+8]		
	//		add rsp,8h
	//		mov [rsp],rax
	//		
	template<addr_width::type aw = addr_width::x64>
	static uint32_t insert_stack_manipulator(obf::obf_t<aw>& ctx)
	{
		auto link = ctx.linker->allocate_link();

		dasm::routine_t<aw>& routine = ctx.additional_routines.emplace_back();
		routine.entry_link = link;

		auto& block = routine.blocks.emplace_back(routine.blocks.end());
		block.termination_type = dasm::termination_type_t::returns;
		block.link = link;

		routine.entry_block = routine.blocks.begin();
		
		auto& insts = block.instructions;



	}

	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(obf::obf_t<aw>& ctx)
	{

	}
};

struct common_prologue_t
{

	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(obf::obf_t<aw>& ctx)
	{
		
	}
};

struct common_epilogue_t
{
	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(obf::obf_t<aw>& ctx)
	{

	}
};

struct common_code_t
{
	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(obf::obf_t<aw>& ctx)
	{

	}
};

