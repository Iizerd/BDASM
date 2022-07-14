#pragma once


#include "obf_structures.h"

// These are all the passes that play around with the original memory of the function
//

namespace obf
{
	// So this is an interesting one, it should be done LAST if you want all instructions to be encrypted
	// The way it works and maintains its thread saftey is by acquiring a spinlock before entering the function
	// then releasing it on exit. The order is as follows
	// 
	//		- Wait to acquire spinlock
	//		- Decrypt routine
	//		- Execute
	//		- Encrypt routine
	//		- Release spinlock
	// 
	//

	struct encrypted_blocks_t
	{
		// Takes a link that represents a byte in memory to use as the spinlock
		//
		template<addr_width::type Addr_width = addr_width::x64>
		static dasm::inst_list_t<Addr_width> acquire_spinlock(uint32_t spinlock_link)
		{
			// continue_wait:
			//   mov al,1
			//   lock cmpxchg [rip+spinlock_offset],al
			//   jnz continue_wait
			//
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static dasm::inst_list_t<Addr_width> release_spinlock(uint32_t spinlock_link)
		{
			// push rax
			// mov al,1
			// lock xchg [rip+spinlock_offset],al
			// pop rax
			//
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static void gen_prologue_epilogue_combo(dasm::inst_t<Addr_width>& inst, dasm::inst_list_t<Addr_width>& prologue, dasm::inst_list_t<Addr_width>& epilogue)
		{
			// For xoring, prologue and epilogue are the same
			//
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static std::pair<dasm::inst_list_t<Addr_width>, dasm::inst_list_t<Addr_width> > encryption_prolog_epilogue(dasm::block_it_t<Addr_width> block)
		{
			dasm::inst_list_t<Addr_width> prologue, epilogue;

			for (auto& inst : block->instructions)
			{
				gen_prologue_epilogue_combo(inst, prologue, epilogue);
			}

			return { prologue, epilogue };
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx)
		{

		}
	};
}
