#pragma once


#include "obf.h"


// Locate places where we know the state of certain flags, then jump based on them
// Example1: trace forward the flag used by a jcc, find where its written to again, and right before then place an opaque
// Example2: find places where constant values are moved into registers, trace forward until they are potentially invalidated and
//		place an opaque right before
// 
// 
// 

	// Trace flags after a previous conditional jump until it is written to, then insert a branch before that
	// using the known flag value
	//
struct opaque_from_flags_t
{
	// Will be using bitwise on the visited member here beacuse we need to differentiate
	//

	constexpr static uint32_t visited_1 = (1 << 0);
	constexpr static uint32_t visited_2 = (1 << 1);

	template<addr_width::type Addr_width = addr_width::x64>
	struct my_context
	{
		dasm::routine_t<Addr_width>& routine;
		obf::context_t<Addr_width>& ctx;
		my_context(dasm::routine_t<Addr_width>& r, obf::context_t<Addr_width>& context)
			: routine(r)
			, ctx(context)
		{}
	};

	template<addr_width::type Addr_width = addr_width::x64>
	static bool multiple_references(my_context<Addr_width>& ctx, dasm::block_it_t<Addr_width> check_block)
	{
		if (check_block == ctx.routine.blocks.end())
			return false;
		uint32_t count = 0;
		for (auto& block : ctx.routine.blocks)
		{
			if (block.fallthrough_block == check_block || block.taken_block == check_block)
				++count;
		}
		return count > 1;
	}

	static xed_iclass_enum_t invert_jcc(xed_iclass_enum_t jcc)
	{
		switch (jcc)
		{
		case XED_ICLASS_JB: return XED_ICLASS_JNB;
		case XED_ICLASS_JBE: return XED_ICLASS_JNBE;
		case XED_ICLASS_JL: return XED_ICLASS_JNL;
		case XED_ICLASS_JLE: return XED_ICLASS_JNLE;
		case XED_ICLASS_JNB: return XED_ICLASS_JB;
		case XED_ICLASS_JNBE: return XED_ICLASS_JBE;
		case XED_ICLASS_JNL: return XED_ICLASS_JL;
		case XED_ICLASS_JNLE: return XED_ICLASS_JLE;
		case XED_ICLASS_JNO: return XED_ICLASS_JO;
		case XED_ICLASS_JNP: return XED_ICLASS_JP;
		case XED_ICLASS_JNS: return XED_ICLASS_JS;
		case XED_ICLASS_JNZ: return XED_ICLASS_JZ;
		case XED_ICLASS_JO: return XED_ICLASS_JNO;
		case XED_ICLASS_JP: return XED_ICLASS_JNP;
		case XED_ICLASS_JS: return XED_ICLASS_JNS;
		case XED_ICLASS_JZ: return XED_ICLASS_JNZ;
		default: return XED_ICLASS_INVALID;
		}
	}

	static bool is_bad_iclass(xed_iclass_enum_t iclass)
	{
		switch (iclass)
		{
		case XED_ICLASS_CALL_NEAR:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_RET_NEAR:
			return true;
		}
		return false;
	}

	template<addr_width::type Addr_width = addr_width::x64>
	static void reset_visited_2(dasm::routine_t<Addr_width>& routine)
	{
		for (auto& block : routine.blocks)
		{
			block.visited &= ~visited_2;
		}
	}

	template<addr_width::type Addr_width = addr_width::x64>
	static uint32_t find_random_link(my_context<Addr_width>& ctx)
	{
		auto routine_it = ctx.ctx.obf_routine_list.begin();

		std::advance(routine_it, rand() % ctx.ctx.obf_routine_list.size());

		auto block_it_t = routine_it->m_routine.blocks.begin();

		auto inst_it = block_it_t->instructions.begin();
		std::advance(inst_it, rand() % block_it_t->instructions.size());

		return inst_it->my_link;
	}


	template<addr_width::type Addr_width = addr_width::x64>
	static void recursive_trace_and_place(dasm::block_it_t<Addr_width> block, my_context<Addr_width>& ctx, xed_iclass_enum_t iclass, const xed_flag_set_t* flag_set, bool taken)
	{
		if (block->visited & visited_2)
			return;

		auto place_jcc = [&](dasm::inst_it_t<Addr_width> inst_it)
		{
			//printf("opaqued.\n");

			if (taken)
				iclass = invert_jcc(iclass);

			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

			auto jcc = block->instructions.emplace(inst_it);
			jcc->decode(
				buffer,
				encode_inst_in_place(
					buffer,
					addr_width::machine_state<Addr_width>::value,
					iclass,
					32,
					xed_relbr(0, 32)
				)
			);
			jcc->my_link = ctx.ctx.linker.allocate_link();
			jcc->used_link = find_random_link(ctx);
			jcc->original_rva = 0;
			jcc->flags |= dasm::inst_flag::rel_br;

		};

		for (auto inst_it = block->instructions.begin(); inst_it != block->instructions.end(); ++inst_it)
		{
			auto simple_flag = xed_decoded_inst_get_rflags_info(&inst_it->decoded_inst);
			if (is_bad_iclass(xed_decoded_inst_get_iclass(&inst_it->decoded_inst)) || (simple_flag && (flag_set->flat & (xed_simple_flag_get_undefined_flag_set(simple_flag)->flat | xed_simple_flag_get_written_flag_set(simple_flag)->flat))))
			{
				place_jcc(inst_it);

				return;
			}
		}


		/*	block->visited |= visited_2;
			if (!multiple_references(ctx, block->fallthrough_block) && !multiple_references(ctx, block->taken_block))
				block->invoke_for_next(recursive_trace_and_place<Addr_width>, ctx, iclass, flag_set, taken);
*/


		switch (block->termination_type)
		{
		case dasm::termination_type_t::invalid:
		case dasm::termination_type_t::returns:
			break;

		case dasm::termination_type_t::unconditional_br:
			if (!multiple_references(ctx, block->taken_block))
				recursive_trace_and_place(block->taken_block, ctx, iclass, flag_set, taken);
			else
				place_jcc(std::prev(block->instructions.end()));
			break;

		case dasm::termination_type_t::conditional_br:
			if (!multiple_references(ctx, block->taken_block) && !multiple_references(ctx, block->fallthrough_block))
			{
				recursive_trace_and_place(block->taken_block, ctx, iclass, flag_set, taken);
				recursive_trace_and_place(block->fallthrough_block, ctx, iclass, flag_set, taken);
			}
			else
				place_jcc(std::prev(block->instructions.end()));
			break;
		case dasm::termination_type_t::fallthrough:
			if (!multiple_references(ctx, block->fallthrough_block))
				recursive_trace_and_place(block->fallthrough_block, ctx, iclass, flag_set, taken);
			else
				place_jcc(block->instructions.end());
			break;
		case dasm::termination_type_t::undetermined_unconditional_br:
			place_jcc(std::prev(block->instructions.end()));
			break;
		case dasm::termination_type_t::unknown_logic:
			break;
		}
	}

	template<addr_width::type Addr_width = addr_width::x64>
	static void recursive_application(dasm::block_it_t<Addr_width> block, my_context<Addr_width>& ctx)
	{
		if (block->visited & visited_1)
			return;


		if (block->termination_type == dasm::termination_type_t::conditional_br)
		{
			auto simple_flag = xed_decoded_inst_get_rflags_info(&block->instructions.back().decoded_inst);
			auto read_flags = xed_simple_flag_get_read_flag_set(simple_flag);
			auto iclass = xed_decoded_inst_get_iclass(&block->instructions.back().decoded_inst);


			ctx.routine.reset_visited_bit(1);
			if (!multiple_references(ctx, block->taken_block))
				recursive_trace_and_place(block->taken_block, ctx, iclass, read_flags, true);


			ctx.routine.reset_visited_bit(1);
			if (!multiple_references(ctx, block->fallthrough_block))
				recursive_trace_and_place(block->fallthrough_block, ctx, iclass, read_flags, false);

		}


		block->visited |= visited_1;
		block->invoke_for_next(recursive_application<Addr_width>, ctx);
	}


	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{
		routine.reset_visited();

		my_context<Addr_width> my_context = { routine, ctx };

		recursive_application(routine.entry_block, my_context);

		return obf::pass_status_t::success;
	}
};

// Search for constant non zero values. Trace forward until its written to and place a test and jcc
// right before. make sure flags are clobbered so they dont need to be preserved.
//  mov reg,nonzero
//  or reg,nonzero
//  
struct opaque_from_const_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{

	}
};

struct opaque_code_copy_t
{
	template<addr_width::type Addr_width = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<Addr_width>& routine, obf::context_t<Addr_width>& ctx)
	{

	}
};