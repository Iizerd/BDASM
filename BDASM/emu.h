#pragma once


#include "addr_width.h"
#include "inst.h"


namespace obf
{
	namespace emu
	{

		template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
		inline dasm::inst_list_t<Addr_width> emulate_call(dasm::inst_t<Addr_width> const& call_inst)
		{
			dasm::inst_list_t<Addr_width> result;
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
			uint32_t disp_size = 0;

			disp_size += result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				addr_width_to_machine_state<Addr_width>::value,
				XED_ICLASS_XCHG,
				addr_width_to_bits<Addr_width>::value,
				xed_mem_b(get_max_reg_size<XED_REG_RSP, Addr_width>::value, addr_width_to_bits<Addr_width>::value),
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value)
			));

			switch (xed_decoded_inst_get_iform_enum(&call_inst->decoded_inst))
			{
			case XED_IFORM_CALL_NEAR_GPRv:

				break;
			case XED_IFORM_CALL_NEAR_MEMv:

				break;
			case XED_IFORM_CALL_NEAR_RELBRd:
			case XED_IFORM_CALL_NEAR_RELBRz:
				encode_inst_in_place(buffer,
					addr_width_to_machine_state<Addr_width>::value,
					XED_ICLASS_JMP,
					addr_width_to_bits<Addr_width>::value,
					xed_relbr(0, 32)
				);
				break;
			}

			disp_size += result.emplace_back().decode(buffer, XED_MAX_INSTRUCTION_BYTES);
			result.back().used_symbol = call_inst.used_symbol;

			result.emplace_front().decode(buffer, encode_inst_in_place(buffer,
				addr_width_to_machine_state<Addr_width>::value,
				XED_ICLASS_LEA,
				addr_width_to_bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value),
				xed_mem_bd(get_max_reg_size<XED_REG_RIP, Addr_width>::value, xed_disp(disp_size, 32), addr_width_to_bits<Addr_width>::value)
			));

			result.emplace_front().decode(buffer, encode_inst_in_place(buffer,
				addr_width_to_machine_state<Addr_width>::value,
				XED_ICLASS_PUSH,
				addr_width_to_bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value)
			));

			return result;
		}

		template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
		inline dasm::inst_list_t<Addr_width> ret()
		{
			dasm::inst_list_t<Addr_width> result;
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




