#pragma once


#include "addr_width.h"
#include "inst.h"


namespace obf
{
	namespace emu
	{
		template<address_width Addr_width = address_width::x64>
		inline inst_list_t<Addr_width> ret()
		{
			inst_list_t<Addr_width> result;
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
			xed_state_t machine_state = addr_width_to_machine_state<Addr_width>::value;

			uint32_t jmp_size = result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				addr_width_to_machine_state<Addr_width>::value,
				XED_ICLASS_JMP,
				addr_width_to_bits<Addr_width>::value,
				xed_mem_bd(get_max_reg_size<XED_REG_RIP, Addr_width>::value, xed_disp(0, 32), addr_width_to_bits<Addr_width>::value)
			));

			
			result.emplace_front().decode(buffer, encode_inst_in_place(buffer,
				addr_width_to_machine_state<Addr_width>::value,
				XED_ICLASS_POP,
				addr_width_to_bits<Addr_width>::value,
				xed_mem_bd(get_max_reg_size<XED_REG_RIP, Addr_width>::value, xed_disp(jmp_size, 32), addr_width_to_bits<Addr_width>::value)
			));

			result.splice(result.end(), generate_nops<Addr_width>(addr_width_to_bytes<Addr_width>::value));
			return result;
		}
	}
}




