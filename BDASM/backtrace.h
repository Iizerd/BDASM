#pragma once

#include "dasm.h"



// Trace backwards in the current block to see if a register equals another
// This is useful when the compiler decodes to randomly do something like:
//
//		mov rax,rsp
//		mov [rax+offset],val
//		
// Or some other annoyingly weird thing. this can follow something like this:
//		mov rcx,rsp
//		mov rax,rcx
//		mov [rax+10h],rbx
//
template<addr_width::type Addr_width = addr_width::x64>
bool trace_for_reg_alias(dasm::block_t<Addr_width>& block, dasm::inst_it_t<Addr_width> start, xed_reg_enum_t reg1, xed_reg_enum_t reg2)
{
	for (auto rev = std::make_reverse_iterator(start); rev != block.instructions.rend(); ++rev)
	{
		if (auto iform = xed_decoded_inst_get_iform_enum(&rev->decoded_inst); 
			(iform == XED_IFORM_MOV_GPRv_GPRv_89 || iform == XED_IFORM_MOV_GPRv_GPRv_8B) &&
			reg1 == xed_decoded_inst_get_reg(&rev->decoded_inst, XED_OPERAND_REG0))
		{
			auto right_reg = xed_decoded_inst_get_reg(&rev->decoded_inst, XED_OPERAND_REG0);
			if (reg2 == right_reg)
				return true;
			else
				reg1 = right_reg;
		}
		else
		{
			auto inst = xed_decoded_inst_inst(&rev->decoded_inst);
			auto num_operands = xed_decoded_inst_noperands(&rev->decoded_inst);

			for (uint32_t i = 0; i < num_operands; ++i)
			{
				auto operand = xed_inst_operand(inst, i);
				if (xed_operand_written(operand))
				{
					auto operand_name = xed_operand_name(operand);
					if (xed_operand_is_register(operand_name))
					{
						if (reg1 == xed_decoded_inst_get_reg(&rev->decoded_inst, operand_name))
							return false;
					}
				}
			}
		}
	}

	system("pause");
	return false;
}
