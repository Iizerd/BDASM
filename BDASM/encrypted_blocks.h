#pragma once

#include <random>

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
	//		- Decrypt block
	//		- Execute block
	//		- Encrypt block
	//		- Release spinlock
	// 
	//

	struct encrypted_blocks_t
	{
		template<addr_width::type Addr_width = addr_width::x64, typename Xor_val_type>
		static bool post_encode_xor_callback(dasm::inst_t<Addr_width>* inst, uint8_t* target, dasm::linker_t* linker, pex::binary_t<Addr_width>* bin, Xor_val_type xor_val)
		{
			*reinterpret_cast<Xor_val_type*>(target) ^= xor_val;
			return true;
		}

		// Takes a link that represents a byte in memory to use as the spinlock
		//
		template<addr_width::type Addr_width = addr_width::x64>
		static dasm::inst_list_t<Addr_width> acquire_spinlock(context_t<Addr_width>& ctx, uint32_t spinlock_link)
		{
			//	 pushfq
			//	 push rax
			// continue_wait:
			//   mov al,0x90
			//   lock xchg [rip+spinlock_offset],al
			//   test al,al
			//   jnz continue_wait
			//	 pop rax
			//   popfq
			//

			uint32_t continue_wait = ctx.linker->allocate_link();

			dasm::inst_list_t<Addr_width> result;

			
			result.emplace_back(
				XED_ICLASS_PUSHF,
				addr_width::bits<Addr_width>::value
			).common_edit(ctx.linker->allocate_link(), 0, 0);


			result.emplace_back(
				XED_ICLASS_PUSH,
				addr_width::bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value)
			).common_edit(ctx.linker->allocate_link(), 0, 0);

			result.emplace_back(
				XED_ICLASS_MOV,
				8,
				xed_reg(XED_REG_AL),
				xed_imm0(0x90, 8)
			).common_edit(continue_wait, 0, 0);


			result.emplace_back(
				XED_ICLASS_XCHG,
				8,
				xed_mem_bd(
					get_max_reg_size<XED_REG_RIP, Addr_width>::value,
					xed_disp(0, 32),
					8
				),
				xed_reg(XED_REG_AL)
			).common_edit(ctx.linker->allocate_link(), spinlock_link, dasm::inst_flag::disp);

		
			result.emplace_back(
				XED_ICLASS_TEST,
				8,
				xed_reg(XED_REG_AL),
				xed_reg(XED_REG_AL)
			).common_edit(ctx.linker->allocate_link(), 0, 0);


			result.emplace_back(
				XED_ICLASS_JZ,
				8,
				xed_relbr(0, 32)
			).common_edit(ctx.linker->allocate_link(), continue_wait, dasm::inst_flag::rel_br);


			result.emplace_back(
				XED_ICLASS_POP,
				addr_width::bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value)
			).common_edit(ctx.linker->allocate_link(), 0, 0);

			return result;
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static dasm::inst_list_t<Addr_width> release_spinlock(context_t<Addr_width>&ctx, uint32_t spinlock_link)
		{
			// push rax
			// mov al,0
			// lock xchg [rip+spinlock_offset],al
			// pop rax
			//

			uint32_t continue_wait = ctx.linker->allocate_link();

			dasm::inst_list_t<Addr_width> result;

			result.emplace_back(
				XED_ICLASS_PUSH,
				addr_width::bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value)
			).common_edit(ctx.linker->allocate_link(), 0, 0);


			result.emplace_back(
				XED_ICLASS_MOV,
				8,
				xed_reg(XED_REG_AL),
				xed_imm0(0, 8)
			).common_edit(ctx.linker->allocate_link(), 0, 0);


			result.emplace_back(
				XED_ICLASS_XCHG,
				8,
				xed_mem_bd(
					get_max_reg_size<XED_REG_RIP, Addr_width>::value,
					xed_disp(0, 32),
					8
				),
				xed_reg(XED_REG_AL)
			).common_edit(ctx.linker->allocate_link(), spinlock_link, dasm::inst_flag::disp);

			result.emplace_back(
				XED_ICLASS_POP,
				addr_width::bits<Addr_width>::value,
				xed_reg(get_max_reg_size<XED_REG_RAX, Addr_width>::value)
			).common_edit(ctx.linker->allocate_link(), 0, 0);

			return result;
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static void shuffle_list(dasm::inst_list_t<Addr_width>& list)
		{
			for (uint32_t i = 0; i < 8; ++i)
			{
				for (auto inst_it = list.begin(); inst_it != list.end();)
				{
					auto next = std::next(inst_it);
					if (rand() % 100 < 50)
						list.splice(list.begin(), list, inst_it);
					inst_it = next;
				}
			}
		}

		static uint8_t encr_width(uint32_t inst_width)
		{
			constexpr static uint8_t table[3] = { 1,2,4 };

			if (inst_width > 3)
				return table[rand() % 3];
			else if (inst_width > 1)
				return table[rand() % 2];
			else
				return 1;
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static void gen_encryption_pair(context_t<Addr_width>& ctx, dasm::inst_t<Addr_width>& inst, dasm::inst_list_t<Addr_width>& prologue, dasm::inst_list_t<Addr_width>& epilogue, bool post_encode)
		{
			// For xoring, prologue and epilogue are the same
			//

			auto len = inst.length();
			auto width = encr_width(len);
			auto width_bits = width * 8;

			uint32_t val = rand();

			prologue.emplace_back(
				XED_ICLASS_XOR,
				width_bits,
				xed_mem_bd(
					get_max_reg_size<XED_REG_RIP, Addr_width>::value,
					xed_disp(0, 32),
					width_bits
				),
				xed_imm0(val, width_bits)
			).common_edit(ctx.linker->allocate_link(), inst.my_link, dasm::inst_flag::disp);

			epilogue.emplace_back(
				XED_ICLASS_XOR,
				width_bits,
				xed_mem_bd(
					get_max_reg_size<XED_REG_RIP, Addr_width>::value,
					xed_disp(0, 32),
					width_bits
				),
				xed_imm0(val, width_bits)
			).common_edit(ctx.linker->allocate_link(), inst.my_link, dasm::inst_flag::disp);

			if (post_encode)
			{

				switch (width)
				{
				case 1:
					inst.encode_callback = std::bind(post_encode_xor_callback < Addr_width, uint8_t>,
						std::placeholders::_1,
						std::placeholders::_2,
						std::placeholders::_3,
						std::placeholders::_4,
						val
					);
					break;
				case 2:
					inst.encode_callback = std::bind(post_encode_xor_callback < Addr_width, uint16_t>,
						std::placeholders::_1,
						std::placeholders::_2,
						std::placeholders::_3,
						std::placeholders::_4,
						val
					);
					break;
				case 4:
					inst.encode_callback = std::bind(post_encode_xor_callback < Addr_width, uint32_t>,
						std::placeholders::_1,
						std::placeholders::_2,
						std::placeholders::_3,
						std::placeholders::_4,
						val
					);
					break;
				default:
					std::printf("Invalid width for encryption.\n");
				}
			}
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static std::pair<dasm::inst_list_t<Addr_width>, dasm::inst_list_t<Addr_width> > encryption(context_t<Addr_width>& ctx, dasm::block_t<Addr_width>& block)
		{
			dasm::inst_list_t<Addr_width> prologue, epilogue;

			for (auto& inst : block.instructions)
			{
				//if (inst.flags & dasm::inst_flag::block_terminator)
				//	break;

				if (!inst.encode_callback)
				{
					inst.redecode();
					gen_encryption_pair(ctx, inst, prologue, epilogue, !(inst.flags & dasm::inst_flag::block_terminator));
				}
			}

			shuffle_list(prologue);
			//shuffle_list(epilogue);


			prologue.emplace_back(
				XED_ICLASS_POPF,
				addr_width::bits<Addr_width>::value
			).common_edit(ctx.linker->allocate_link(), 0, 0);

			epilogue.emplace_front(
				XED_ICLASS_PUSHF,
				addr_width::bits<Addr_width>::value
			).common_edit(ctx.linker->allocate_link(), 0, 0);

			epilogue.emplace_back(
				XED_ICLASS_POPF,
				addr_width::bits<Addr_width>::value
			).common_edit(ctx.linker->allocate_link(), 0, 0);

			return { prologue, epilogue };
		}

		template<addr_width::type Addr_width = addr_width::x64>
		static pass_status_t pass(dasm::routine_t<Addr_width>& routine, context_t<Addr_width>& ctx, bool spinlock = true)
		{
			/*auto [prologue, epilogue] = encryption();*/

			for (auto& block : routine.blocks)
			{
				// Now we need to find where to insert the epilogue and spinlock release
				//
				auto inst_it = std::prev(block.instructions.end());
				uint32_t terminator_size = 0;

				while (true)
				{
					if (!(inst_it->flags & dasm::inst_flag::block_terminator))
					{
						++inst_it;
						break;
					}

					++terminator_size;
					
					if (inst_it == block.instructions.begin())
						break;

					--inst_it;
				}


				// Make sure there are actually some instructions we can encrypt
				//
				if (block.instructions.size() <= terminator_size)
					continue;


				uint32_t spinlock_link = ctx.linker->allocate_link();

				// Gen the prologue and epilogues here, prepend and append them
				//
				auto [prologue, epilogue] = encryption(ctx, block);

				block.instructions.splice(block.instructions.begin(), prologue);
				block.instructions.splice(inst_it, epilogue);

				// Now add the spinlock acquire and release
				//
				auto acquire = acquire_spinlock(ctx, spinlock_link);
				auto release = release_spinlock(ctx, spinlock_link);

				block.instructions.splice(block.instructions.begin(), acquire);
				block.instructions.splice(inst_it, release);

				block.instructions.emplace_back(
					XED_ICLASS_NOP,
					32
				).common_edit(spinlock_link, 0, dasm::inst_flag::block_terminator);
			}

			return pass_status_t::success;
		}
	};
}
