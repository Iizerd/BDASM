#pragma once

#include "obf.h"
#include "flags.h"
#include "size_casting.h"

struct constant_encryption_t
{
	template<addr_width::type aw = addr_width::x64>
	static uint32_t encrypted_const_custom_encoder(dasm::inst_t<aw>* inst, pex::binary_t<aw>* bin, dasm::linker_t* linker, uint8_t* dest, uint32_t xor_key)
	{
		uint32_t expected_length = inst->length();

		inst->resolve_deltas(bin, linker, dest, expected_length);

		auto imm = xed_decoded_inst_get_unsigned_immediate(&inst->decoded_inst);
		//printf("Custom encoder called %X %X %X\n", imm, inst->used_link, inst->flags);
		imm ^= xor_key;
		xed_decoded_inst_set_immediate_unsigned_bits(&inst->decoded_inst, imm, xed_decoded_inst_get_immediate_width_bits(&inst->decoded_inst));

		uint32_t ilen = 0;
		xed_error_enum_t err = xed_encode(&inst->decoded_inst, dest, XED_MAX_INSTRUCTION_BYTES, &ilen);
		if (XED_ERROR_NONE != err)
			return 0;

		if (ilen != expected_length)
		{
			printf("Encoded inst length did not match what was expected.\n");
			return 0;
		}

		return ilen;
	}

	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<aw>& routine, obf::obf_t<aw>& ctx)
	{
		for (auto block_it = routine.blocks.begin(); block_it != routine.blocks.end(); ++block_it)
		{
			for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end();)
			{
				auto next = std::next(inst_it);

				switch (inst_it->iform())
				{
				case XED_IFORM_MOV_GPRv_IMMv:
				case XED_IFORM_MOV_GPRv_IMMz:
				case XED_IFORM_MOV_GPR8_IMMb_B0:
				{
					auto imm_width = xed_decoded_inst_get_immediate_width_bits(&inst_it->decoded_inst);
					if (imm_width > 32 || xed_decoded_inst_get_immediate_is_signed(&inst_it->decoded_inst) || inst_it->custom_encoder)
						break;

					xed_flag_set_t ledger;
					ledger.s.of = 1;
					ledger.s.cf = 1;
					ledger.s.sf = 1;
					ledger.s.zf = 1;
					ledger.s.pf = 1;
					ledger.s.af = 1;
					bool need_to_save = dasm::flags_clobbered_before_use(routine, block_it, next, ledger);
					if (need_to_save)
						printf("Dont need to save.\n");
					else
						printf("Do need to save them.\n");

					//need_to_save = true;


					//printf("Found mov gpr,imm to obfuscate.\n");
					auto reg = xed_decoded_inst_get_reg(&inst_it->decoded_inst, XED_OPERAND_REG0);
					auto max_reg = change_reg_width(reg, addr_width::reg_width<aw>::value);
					uint64_t imm_value = xed_decoded_inst_get_unsigned_immediate(&inst_it->decoded_inst);
					//printf("Imm value %llu %X\n", imm_value, inst_it->original_rva);
					uint32_t xor_key = (((static_cast<uint64_t>(rand()) << 16) |
						(static_cast<uint64_t>(rand()) << 0)) & 0xFFFFFFFF);

					switch (imm_width)
					{
					case 8: xor_key &= 0xFF; break;
					case 16: xor_key &= 0xFFFF; break;
					}

					dasm::inst_list_t<aw> enc;
					enc.emplace_back(
						XED_ICLASS_PUSH,
						addr_width::bits<aw>::value,
						xed_imm0(imm_value, imm_width)
					).common_edit(ctx.linker->allocate_link(), inst_it->used_link, inst_it->flags);
					enc.back().custom_encoder = std::bind(encrypted_const_custom_encoder<aw>,
						std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, xor_key);

					if (!need_to_save)
						enc.emplace_back(
							XED_ICLASS_PUSHF,
							addr_width::bits<aw>::value
						).common_edit(ctx.linker->allocate_link(), 0, 0);

					enc.emplace_back(
						XED_ICLASS_MOV,
						addr_width::bits<aw>::value,
						xed_reg(max_reg),
						xed_imm0(xor_key, addr_width::bits<aw>::value)
					).common_edit(ctx.linker->allocate_link(), 0, 0);

					if (!need_to_save)
					{
						enc.emplace_back(
							XED_ICLASS_XOR,
							addr_width::bits<aw>::value,
							xed_mem_bd(
								max_reg_width<XED_REG_RSP, aw>::value,
								xed_disp(8, 8),
								addr_width::bits<aw>::value
							),
							xed_reg(max_reg)
						).common_edit(ctx.linker->allocate_link(), 0, 0);

						enc.emplace_back(
							XED_ICLASS_POPF,
							addr_width::bits<aw>::value
						).common_edit(ctx.linker->allocate_link(), 0, 0);
					}
					else
					{
						enc.emplace_back(
							XED_ICLASS_XOR,
							addr_width::bits<aw>::value,
							xed_mem_b(
								max_reg_width<XED_REG_RSP, aw>::value,
								addr_width::bits<aw>::value
							),
							xed_reg(max_reg)
						).common_edit(ctx.linker->allocate_link(), 0, 0);
					}

					enc.emplace_back(
						XED_ICLASS_POP,
						addr_width::bits<aw>::value,
						xed_reg(max_reg)
					).common_edit(ctx.linker->allocate_link(), 0, 0);

					block_it->instructions.splice(inst_it, enc);
					block_it->instructions.erase(inst_it);
					break;
				}
				case XED_IFORM_PUSH_IMMb:
				case XED_IFORM_PUSH_IMMz:
				{
					printf("Found a push imm to obfuscate.\n");
					break;
				}

				}

				//auto inst = inst_it->inst();
				//auto num_operands = isnt->noperands();
				//for (uint32_t i = 0; i < num_operands; ++i)
				//{
				//	auto operand_name = xed_operand_name(xed_inst_operand(inst, i));
				//	if (operand_name == XED_OPERAND_IMM0/* || operand_name == XED_OPERAND_IMM0SIGNED*/)
				//	{
				//		
				//	}
				//}

				inst_it = next;
			}
		}
		return obf::pass_status_t::success;
	}
};