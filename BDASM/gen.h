#pragma once

#include "addr_width.h"
#include "inst.h"
#include "dasm.h"

namespace obf
{
	namespace gen
	{
		constexpr uint32_t max_nop_size = 9;
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> nops(uint32_t length)
		{
			dasm::inst_list_t<Addr_width> result;
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


		// This is for creating an obfuscated jump within the original binary. One that will jump
		// to the new place where the function is in a "stealthy way"
		//
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> routine_jump(dasm::inst_routine_t<Addr_width>& routine)
		{

		}


		// These are for replacing access to the data section with gadgets that load the data from an
		// absolute address. For example one patched in by the IFF loader.
		//
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> abs_data_lea(dasm::inst_t<Addr_width>& accessing_inst)
		{

		}
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> abs_data_mov(dasm::inst_t<Addr_width>& accessing_inst)
		{

		}

		// If a routine is marked with MARKER_ATTRIBUTE_EXECUTED_ONCE, the obfuscator will generate one of
		// these to delete the function after its run, probably some gadget that replaces each ret inst.
		// This can be used on the aforementioned routine_jump gadgets
		//
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> inst_deleter(dasm::inst_list_t<Addr_width>& list_to_delete)
		{
			// For now ill just do a simple loop to zero it, maybe do advanced moving in the future
			// Make it look like data? => mov byte_ptr[rax+rcx], cl ???
			// 
			// 
			//	push rax
			//	push rcx
			//	mov ecx,inst_list_size
			//	lea rax,[rip+off_to_first_inst]
			// continue_loop:
			//	mov byte ptr[rax+rcx], 0
			//	sub ecx,1
			//	jnz continue_loop
			//	pop rcx
			//	pop rax
			// 
			//


		}
	}
}







