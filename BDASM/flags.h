#pragma once


#include "dasm.h"



namespace dasm
{
	// This routine determines if the flags edited by 'start' in question are actually used by iterating forward until
	// they are either accessed, or completely overwritten
	// 
	// This clears 31th bit of visited for all blocks. Make sure you dont use.
	//
	template<addr_width::type aw = addr_width::x64>
	bool flags_clobbered(routine_t<aw>& routine, block_it_t<aw> block, inst_it_t<aw> start)
	{
		routine.reset_visited_bit(31);

		xed_flag_set_t ledger;
		const xed_simple_flag_t* start_flags = xed_decoded_inst_get_rflags_info(&start->DecodedInst);
		ledger.flat = (xed_simple_flag_get_written_flag_set(start_flags)->flat | xed_simple_flag_get_undefined_flag_set(start_flags)->flat);
		
		auto it = std::next(start);
		while (it != block->instructions.end())
		{
			const xed_simple_flag_t* inst_flag = xed_decoded_inst_get_rflags_info(&it->decoded_inst);

			if (ledger.flat & xed_simple_flag_get_read_flag_set(inst_flag)->flat)
				return true;

			ledger.flat &= ~(xed_simple_flag_get_written_flag_set(inst_flag)->flat | xed_simple_flag_get_undefined_flag_set(inst_flag)->flat);

			++it;
		}
		return false;
	}

	// This does the same as above but with an arbitrary flagset
	//
	template<addr_width::type aw = addr_width::x64>
	bool flags_clobbered(routine_t<aw>& routine, block_t<aw>& block, inst_it_t<aw> start, xed_flag_set_t flagset)
	{
		
	}

	// Trace forward until the flags we are concerned about are completely overwritten.
	//
	template<addr_width::type aw = addr_width::x64>
	std::pair<block_it_t<aw>, inst_it_t<aw>> trace_to_overwrite()
	{

	}

	template<addr_width::type aw = addr_width::x64>
	bool flags_clobbered_before_use_recursion(block_it_t<aw> block, block_it_t<aw> start_block, inst_it_t<aw> start_inst, xed_flag_set_t ledger)
	{
		if (block->visited & (1 << 31))
			return true;

		block->visited |= (1 << 31);

		for (auto inst_it = block->instructions.begin(); inst_it != block->instructions.end(); ++inst_it )
		{
			auto cur_inst_flags = xed_decoded_inst_get_rflags_info(&inst_it->decoded_inst);
			
			if (cur_inst_flags)
			{
				// Make sure if we are in the starting block, we dont test the instruction that actually set these flags.
				// If we found the the inst that did, then we know they aint clobbered.
				//
				if (block == start_block && inst_it != start_inst)
					return true;

				// Check to see if the current inst uses some flags that we changed
				//
				if (ledger.flat & xed_simple_flag_get_read_flag_set(cur_inst_flags)->flat)
					return false;

				// Update the current flags so that they reflect what is clobbered by the current inst
				//
				ledger.flat &= ~(xed_simple_flag_get_written_flag_set(cur_inst_flags)->flat | xed_simple_flag_get_undefined_flag_set(cur_inst_flags)->flat);

				// Check and return if all flags are clobbered
				//
				if (ledger.flat == 0)
					return true;
			}
		}
		
		return block->invoke_for_next_check_bool(flags_clobbered_before_use_recursion<aw>, start_block, start_inst, ledger);
	}


	// Trace forward following control flow to see if the flags set by the 'start' instruction are clobbered
	// before they are used by a conditional.
	// 
	// This itself clobberes bit 31 in block_t::visited.
	//
	template<addr_width::type aw = addr_width::x64>
	bool flags_clobbered_before_use(routine_t<aw>& routine, block_it_t<aw> start_block, inst_it_t<aw> start_inst, xed_flag_set_t ledger)
	{
		routine.reset_visited_bit(31);

		//xed_flag_set_t ledger;
		//auto start_flags = xed_decoded_inst_get_rflags_info(&start_inst->decoded_inst);
		//ledger.flat = (xed_simple_flag_get_written_flag_set(start_flags)->flat | xed_simple_flag_get_undefined_flag_set(start_flags)->flat);

		// This first loop iterates to the end of the current block, without setting its visited bit so that the recursion can 
		// visit it and trace to the start instruction.
		//
		for (auto cur_inst = start_inst; cur_inst != start_block->instructions.end(); ++cur_inst)
		{
			auto cur_inst_flags = xed_decoded_inst_get_rflags_info(&cur_inst->decoded_inst);

			if (cur_inst_flags)
			{
				if (ledger.flat & xed_simple_flag_get_read_flag_set(cur_inst_flags)->flat)
					return false;

				ledger.flat &= ~(xed_simple_flag_get_written_flag_set(cur_inst_flags)->flat | xed_simple_flag_get_undefined_flag_set(cur_inst_flags)->flat);

				if (ledger.flat == 0)
					return true;
			}
		}

		return start_block->invoke_for_next_check_bool(flags_clobbered_before_use_recursion<aw>, start_block, start_inst, ledger);
	}

}

