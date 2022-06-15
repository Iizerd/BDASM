#pragma once

#include "addr_width.h"
#include "inst.h"
#include "dasm.h"

namespace obf
{
	namespace gen
	{
		// Bp based stack frame
		//
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> enter_stack_frame(int32_t alloc_size)
		{
			// push rbp
			// mov rbp,rsp
			// sub rsp,alloc_size
			//
			dasm::inst_list_t<Addr_width> result;
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

			// push
			//
			result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				dasm::addr_width::machine_state<Addr_width>::value,
				XED_ICLASS_PUSH,
				dasm::addr_width::bits<Addr_width>::value,
				xed_reg(dasm::get_max_reg_size<XED_REG_RBP, Addr_width>::value)
			));

			// mov
			//
			result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				dasm::addr_width::machine_state<Addr_width>::value,
				XED_ICLASS_MOV,
				dasm::addr_width::bits<Addr_width>::value,
				xed_reg(dasm::get_max_reg_size<XED_REG_RBP, Addr_width>::value),
				xed_reg(dasm::get_max_reg_size<XED_REG_RSP, Addr_width>::value)
			));

			// sub
			// This needs to be replaced with some 'required_size' thing which says how many 
			// bits are required to store the immediate.
			//
			result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				dasm::addr_width::machine_state<Addr_width>::value,
				XED_ICLASS_SUB,
				dasm::addr_width::bits<Addr_width>::value,
				xed_reg(dasm::get_max_reg_size<XED_REG_RSP, Addr_width>::value),
				xed_imm0(alloc_size, 32)
			));

			return result;
		}
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> leave_stack_frame(int32_t alloc_size)
		{
			// mov rsp,rbp
			// pop rbp
			//
			dasm::inst_list64_t result;
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

			// mov
			//
			result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				dasm::addr_width::machine_state<Addr_width>::value,
				XED_ICLASS_MOV,
				dasm::addr_width::bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RSP, Addr_width>::value),
				xed_reg(get_max_reg_size<XED_REG_RBP, Addr_width>::value)
			));

			// push
			//
			result.emplace_back().decode(buffer, encode_inst_in_place(buffer,
				dasm::addr_width::machine_state<Addr_width>::value,
				XED_ICLASS_POP,
				dasm::addr_width::bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RBP, Addr_width>::value)
			));

			return result;
		}


		// Real generic prologue that stores fastcall registers into the home space
		//
		template<dasm::address_width Addr_width = dasm::address_width::x64>
		inline dasm::inst_list_t<Addr_width> fastcall_prologue(int32_t arg_count, int32_t alloc_size)
		{
			dasm::inst_list_t<Addr_width> result;
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

			if constexpr (Addr_width == dasm::address_width::x64)
			{
				if (arg_count > 4)
					arg_count = 4;

				static constexpr xed_reg_enum_t regs[] = { XED_REG_R9, XED_REG_R8, XED_REG_RDX, XED_REG_RCX };
			}
			if constexpr (Addr_width == dasm::address_width::x86)
			{
				if (arg_count > 2)
					arg_count = 2;
			}


			for (int32_t i = 0; i < arg_count; i++)
			{
				result.emplace_back().decode(
					buffer,
					encode_inst_in_place(
						buffer,
						dasm::addr_width::machine_state<Addr_width>::value,
						XED_ICLASS_MOV,
						dasm::addr_width::bits<Addr_width>::value,
						xed_mem_bd(
							dasm::get_max_reg_size<XED_REG_RSP, Addr_width>::value,
							xed_disp(
								dasm::addr_width::bytes<Addr_width>::value * (arg_count - i),
								8
							),
							dasm::addr_width::bits<Addr_width>::value
						),
						xed_reg(dasm::addr_width::fastcall_regs<Addr_width>::regs[i])
					)
				);
			}

			result.splice(result.end(), enter_stack_frame<Addr_width>(alloc_size));

			return result;
		}


		inline constexpr uint32_t max_nop_size = 9;
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







