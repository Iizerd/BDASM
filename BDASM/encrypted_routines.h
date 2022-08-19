//#pragma once
//
//#include <random>
//
//#include "obf.h"
//
//// Very similar to encrypted_blocks_t but this encrypts/decrypts the entire routine at one time
//// This is going to be MUCH(thousands of times) faster for routines that contain loops.
////
//
//// Basic function entry logic:
////	
////		Save registers and flags
////		Acquire logic spinlock
////		mov rax,[rip+counter_offset]
////		test rax,rax
////		jnz no_decrypt
////  
////		Decrypt function here
//// 
////	no_decrypt:
////		add [rip+counter_offset],1
////		Release logic spinlock
////		Restore registers and flags
//// 
//// 
//// 
//// Basic function exit logic:
//// 
////		Save registers and flags
////		Acquire logic spinlock
////		sub [rip+counter_offset],1
////		jnz no_encrypt
//// 
////		Encrypt the function here
//// 
////	no_encrypt:
////		Release logic spinlock
////		Restore registers and flags
////		Function exit terminator(ret or undetermined unconditional jmp)
//// 
//// 
//// I think i dont actually need to save the flags? Since this only happens on entry and exit
//// to a function. I also dont need to save rax on entry.
////
//
//struct encrypted_routine_t
//{
//	template<addr_width::type aw = addr_width::x64, typename Xor_val_type>
//	static bool xor_encode_callback(dasm::inst_t<aw>* inst, uint8_t* target, dasm::linker_t* linker, pex::binary_t<aw>* bin, Xor_val_type xor_val)
//	{
//		*reinterpret_cast<Xor_val_type*>(target) ^= xor_val;
//		return true;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static bool xor_loop_encode_callback(dasm::inst_t<aw>* inst, uint8_t* target, dasm::linker_t* linker, pex::binary_t<aw>* bin, uint8_t xor_val)
//	{
//		auto len = inst->length();
//		for (uint32_t i = 0; i < len; ++i)
//			target[i] ^= xor_val;
//		return true;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static bool spinlock_encode_callback(dasm::inst_t<aw>* inst, uint8_t* target, dasm::linker_t* linker, pex::binary_t<aw>* bin)
//	{
//		*target = 0;
//		return true;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static bool counter_encode_callback(dasm::inst_t<aw>* inst, uint8_t* target, dasm::linker_t* linker, pex::binary_t<aw>* bin)
//	{
//		*reinterpret_cast<uint32_t*>(target) = 0;
//		return true;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static void shuffle_list(dasm::inst_list_t<aw>& list)
//	{
//		for (uint32_t i = 0; i < 8; ++i)
//		{
//			for (auto inst_it = list.begin(); inst_it != list.end();)
//			{
//				auto next = std::next(inst_it);
//				if (rand() % 100 < 50)
//					list.splice(list.begin(), list, inst_it);
//				inst_it = next;
//			}
//		}
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static dasm::inst_list_t<aw> acquire_spinlock(obf::obf_t<aw>& ctx, uint32_t spinlock_link)
//	{
//		// continue_wait:
//		//   mov al,0
//		//   lock xchg [rip+spinlock_offset],al
//		//   test al,al
//		//   jz continue_wait
//		//
//
//		uint32_t continue_wait = ctx.linker->allocate_link();
//
//		dasm::inst_list_t<aw> result;
//
//		result.emplace_back(
//			XED_ICLASS_MOV,
//			8,
//			xed_reg(XED_REG_AL),
//			xed_imm0(1, 8)
//		).common_edit(continue_wait, 0, 0);
//
//		result.emplace_back(
//			XED_ICLASS_XCHG,
//			8,
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				8
//			),
//			xed_reg(XED_REG_AL)
//		).common_edit(ctx.linker->allocate_link(), spinlock_link, dasm::inst_flag::disp);
//
//		result.emplace_back(
//			XED_ICLASS_TEST,
//			8,
//			xed_reg(XED_REG_AL),
//			xed_reg(XED_REG_AL)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_back(
//			XED_ICLASS_JNZ,
//			8,
//			xed_relbr(0, 32)
//		).common_edit(ctx.linker->allocate_link(), continue_wait, dasm::inst_flag::rel_br);
//
//		return result;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static dasm::inst_list_t<aw> release_spinlock(obf::obf_t<aw>& ctx, uint32_t spinlock_link)
//	{
//		// mov al,0
//		// lock xchg [rip+spinlock_offset],al
//		//
//
//		dasm::inst_list_t<aw> result;
//
//		result.emplace_back(
//			XED_ICLASS_MOV,
//			8,
//			xed_reg(XED_REG_AL),
//			xed_imm0(0, 8)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_back(
//			XED_ICLASS_XCHG,
//			8,
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				8
//			),
//			xed_reg(XED_REG_AL)
//		).common_edit(ctx.linker->allocate_link(), spinlock_link, dasm::inst_flag::disp);
//
//		return result;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static dasm::inst_list_t<aw> save_values(obf::obf_t<aw>& ctx)
//	{
//		dasm::inst_list_t<aw> result;
//
//		result.emplace_front(
//			XED_ICLASS_PUSHF,
//			addr_width::bits<aw>::value
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_front(
//			XED_ICLASS_PUSH,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RAX, aw>::value)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_front(
//			XED_ICLASS_PUSH,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RBX, aw>::value)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		return result;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static dasm::inst_list_t<aw> restore_values(obf::obf_t<aw>& ctx)
//	{
//		dasm::inst_list_t<aw> result;
//
//		result.emplace_front(
//			XED_ICLASS_POP,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RBX, aw>::value)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_front(
//			XED_ICLASS_POP,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RAX, aw>::value)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_front(
//			XED_ICLASS_POPF,
//			addr_width::bits<aw>::value
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		return result;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static void build_prologue_logic(obf::obf_t<aw>& ctx, dasm::inst_list_t<aw>& prologue, uint32_t spinlock_link, uint32_t counter_link)
//	{
//		auto no_decrypt = ctx.linker->allocate_link();
//
//		// Setup the beginning
//		//
//		prologue.emplace_front(
//			XED_ICLASS_JNZ,
//			32,
//			xed_relbr(0, 32)
//		).common_edit(ctx.linker->allocate_link(), no_decrypt, dasm::inst_flag::rel_br);
//
//		prologue.emplace_front(
//			XED_ICLASS_TEST,
//			32,
//			xed_reg(XED_REG_EAX),
//			xed_reg(XED_REG_EAX)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		prologue.emplace_front(
//			XED_ICLASS_MOV,
//			32,
//			xed_reg(XED_REG_EAX),
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				32
//			)
//		).common_edit(ctx.linker->allocate_link(), counter_link, dasm::inst_flag::disp);
//
//		prologue.splice(prologue.begin(), acquire_spinlock(ctx, spinlock_link));
//		prologue.splice(prologue.begin(), save_values(ctx));
//
//		// Setup the end.
//		//
//		prologue.emplace_back(
//			XED_ICLASS_ADD,
//			32,
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				32
//			),
//			xed_imm0(1, 8)
//		).common_edit(no_decrypt, counter_link, dasm::inst_flag::disp);
//
//		prologue.splice(prologue.end(), release_spinlock(ctx, spinlock_link));
//		prologue.splice(prologue.end(), restore_values(ctx));
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static void build_epilogue_logic(obf::obf_t<aw>& ctx, dasm::inst_list_t<aw>& epilogue, uint32_t spinlock_link, uint32_t counter_link)
//	{
//
//		// Setup the end
//		//
//		auto spinlock_release = release_spinlock(ctx, spinlock_link);
//		auto no_encrypt = spinlock_release.front().my_link;
//		epilogue.splice(epilogue.end(), spinlock_release);
//		epilogue.splice(epilogue.end(), restore_values(ctx));
//
//
//		// Setup the beginning
//		//
//		epilogue.emplace_front(
//			XED_ICLASS_JNZ,
//			32,
//			xed_relbr(0, 32)
//		).common_edit(ctx.linker->allocate_link(), no_encrypt, dasm::inst_flag::rel_br);
//
//		epilogue.emplace_front(
//			XED_ICLASS_SUB,
//			32,
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				32
//			),
//			xed_imm0(1, 8)
//		).common_edit(ctx.linker->allocate_link(), counter_link, dasm::inst_flag::disp);
//
//		epilogue.splice(epilogue.begin(), acquire_spinlock(ctx, spinlock_link));
//		epilogue.splice(epilogue.begin(), save_values(ctx));
//
//		epilogue.emplace_back(
//			XED_ICLASS_RET_NEAR,
//			addr_width::bits<aw>::value
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//	}
//
//	static uint8_t encr_width(uint32_t inst_width)
//	{
//		constexpr static uint8_t table[3] = { 1,2,4 };
//
//		if (inst_width > 3)
//			return table[rand() % 3];
//		else if (inst_width > 1)
//			return table[rand() % 2];
//		else
//			return 1;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static void gen_encryption_pair(obf::obf_t<aw>& ctx, dasm::inst_t<aw>& inst, dasm::inst_list_t<aw>& prologue, dasm::inst_list_t<aw>& epilogue, bool post_encode)
//	{
//		// For xoring, prologue and epilogue are the same
//		//
//
//		auto len = inst.length();
//		auto width = encr_width(len);
//		auto width_bits = width * 8;
//
//		uint32_t val = rand();
//
//		prologue.emplace_back(
//			XED_ICLASS_XOR,
//			width_bits,
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				width_bits
//			),
//			xed_imm0(val, width_bits)
//		).common_edit(ctx.linker->allocate_link(), inst.my_link, dasm::inst_flag::disp);
//
//		epilogue.emplace_back(
//			XED_ICLASS_XOR,
//			width_bits,
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				width_bits
//			),
//			xed_imm0(val, width_bits)
//		).common_edit(ctx.linker->allocate_link(), inst.my_link, dasm::inst_flag::disp);
//
//		if (post_encode)
//		{
//			switch (width)
//			{
//			case 1:
//				inst.encode_callback = std::bind(xor_encode_callback<aw, uint8_t>,
//					std::placeholders::_1,
//					std::placeholders::_2,
//					std::placeholders::_3,
//					std::placeholders::_4,
//					val
//				);
//				break;
//			case 2:
//				inst.encode_callback = std::bind(xor_encode_callback<aw, uint16_t>,
//					std::placeholders::_1,
//					std::placeholders::_2,
//					std::placeholders::_3,
//					std::placeholders::_4,
//					val
//				);
//				break;
//			case 4:
//				inst.encode_callback = std::bind(xor_encode_callback<aw, uint32_t>,
//					std::placeholders::_1,
//					std::placeholders::_2,
//					std::placeholders::_3,
//					std::placeholders::_4,
//					val
//				);
//				break;
//			default:
//				std::printf("Invalid width for encryption.\n");
//			}
//		}
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static dasm::inst_list_t<aw> gen_encryption_loop(obf::obf_t<aw>& ctx, dasm::block_t<aw>& block, uint8_t xor_key)
//	{
//		//  lea rax,[rip+start_link]
//		//	lea rbx,[rip+end_link]
//		// continue_loop:
//		//	xor byte ptr[rax],xor_key
//		//  add rax,1
//		//  cmp rax,rbx
//		//	jnz continue_loop
//		// 
//		//
//
//		dasm::inst_list_t<aw> result;
//
//		uint32_t start_link = block.instructions.front().my_link;
//		uint32_t end_link = start_link;
//
//		// This is the additional disp added on to the end 
//		int32_t end_add = block.instructions.front().length();
//
//		for (auto& inst : block.instructions)
//		{
//			if (inst.flags & dasm::inst_flag::routine_terminator)
//				break;
//
//			inst.redecode();
//
//			end_link = inst.my_link;
//			end_add = inst.length();
//
//			inst.encode_callback = std::bind(xor_loop_encode_callback<aw>,
//				std::placeholders::_1,
//				std::placeholders::_2,
//				std::placeholders::_3,
//				std::placeholders::_4,
//				xor_key
//			);
//		}
//
//
//		auto continue_loop = ctx.linker->allocate_link();
//
//		result.emplace_back(
//			XED_ICLASS_LEA,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RAX, aw>::value),
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				addr_width::bits<aw>::value
//			)
//		).common_edit(ctx.linker->allocate_link(), start_link, dasm::inst_flag::disp);
//
//		result.emplace_back(
//			XED_ICLASS_LEA,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RBX, aw>::value),
//			xed_mem_bd(
//				max_reg_width<XED_REG_RIP, aw>::value,
//				xed_disp(0, 32),
//				addr_width::bits<aw>::value
//			)
//		).common_edit(ctx.linker->allocate_link(), end_link, dasm::inst_flag::disp);
//		result.back().encode_data.additional_disp = end_add;
//
//		result.emplace_back(
//			XED_ICLASS_XOR,
//			addr_width::bits<aw>::value,
//			xed_mem_b(max_reg_width<XED_REG_RAX, aw>::value, 8),
//			xed_imm0(xor_key, 8)
//		).common_edit(continue_loop, 0, 0);
//
//		result.emplace_back(
//			XED_ICLASS_ADD,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RAX, aw>::value),
//			xed_imm0(1, 8)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_back(
//			XED_ICLASS_CMP,
//			addr_width::bits<aw>::value,
//			xed_reg(max_reg_width<XED_REG_RAX, aw>::value),
//			xed_reg(max_reg_width<XED_REG_RBX, aw>::value)
//		).common_edit(ctx.linker->allocate_link(), 0, 0);
//
//		result.emplace_back(
//			XED_ICLASS_JNZ,
//			addr_width::bits<aw>::value,
//			xed_relbr(0, 8)
//		).common_edit(ctx.linker->allocate_link(), continue_loop, dasm::inst_flag::rel_br);
//
//		return result;
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static void append_block_encryption(obf::obf_t<aw>& ctx, dasm::block_t<aw>& block, dasm::inst_list_t<aw>& prologue, dasm::inst_list_t<aw>& epilogue)
//	{
//		if (block.instructions.size() < 10)
//		{
//			dasm::inst_list_t<aw> p, e;
//			for (auto& inst : block.instructions)
//			{
//				inst.redecode();
//				gen_encryption_pair(ctx, inst, p, e, !(inst.flags & dasm::inst_flag::routine_terminator));
//			}
//			shuffle_list(p);
//			shuffle_list(e);
//
//			prologue.splice(prologue.end(), p);
//			epilogue.splice(epilogue.end(), e);
//		}
//		else
//		{
//			uint8_t xor_key = rand();
//			prologue.splice(prologue.end(), gen_encryption_loop(ctx, block, xor_key));
//			epilogue.splice(epilogue.end(), gen_encryption_loop(ctx, block, xor_key));
//		}
//	}
//
//	template<addr_width::type aw = addr_width::x64>
//	static obf::pass_status_t pass(dasm::routine_t<aw>& routine, obf::obf_t<aw>& ctx)
//	{
//		auto spinlock_link = ctx.linker->allocate_link();
//		auto counter_link = ctx.linker->allocate_link();
//
//		// The prologue and epilogue encryption blocks. These are made up of the two different 
//		// encryption types: rip relative or loop.
//		//
//		dasm::inst_list_t<aw> prologue;
//		auto& epilogue = routine.blocks.emplace_front(routine.blocks.end());
//		epilogue.termination_type = dasm::termination_type_t::unknown_logic;
//		epilogue.link = ctx.linker->allocate_link();
//
//		for (auto block_it = std::next(routine.blocks.begin()); block_it != routine.blocks.end(); ++block_it)
//		{
//			append_block_encryption(ctx, *block_it, prologue, epilogue.instructions);
//		}
//
//		build_prologue_logic(ctx, prologue, spinlock_link, counter_link);
//		build_epilogue_logic(ctx, epilogue.instructions, spinlock_link, counter_link);
//
//		for (auto block_it = std::next(routine.blocks.begin()); block_it != routine.blocks.end(); ++block_it)
//		{
//			if (block_it->termination_type == dasm::termination_type_t::returns ||
//				block_it->termination_type == dasm::termination_type_t::undetermined_unconditional_br)
//			{
//				block_it->instructions.emplace(std::prev(block_it->instructions.end()),
//					XED_ICLASS_CALL_NEAR,
//					32,
//					xed_relbr(0, 32)
//				)->common_edit(ctx.linker->allocate_link(), epilogue.link, dasm::inst_flag::rel_br);
//			}
//		}
//
//		routine.entry_block->instructions.splice(routine.entry_block->instructions.begin(), prologue);
//
//		auto& data_block = routine.blocks.emplace_front(routine.blocks.end());
//		data_block.link = ctx.linker->allocate_link();
//		data_block.instructions.emplace_back(
//			XED_ICLASS_NOP,
//			32
//		).common_edit(spinlock_link, 0, 0);
//		data_block.instructions.back().encode_callback = spinlock_encode_callback<aw>;
//
//		data_block.instructions.emplace_back(
//			XED_ICLASS_NOP4,
//			32
//		).common_edit(counter_link, 0, 0);
//		data_block.instructions.back().encode_callback = counter_encode_callback<aw>;
//
//		return obf::pass_status_t::success;
//	}
//};