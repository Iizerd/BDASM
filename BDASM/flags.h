#pragma once


#include "dasm.h"



namespace obf
{
	// This routine determines if the flags edited by 'start' in question are actually used by iterating forward until
	// they are either accessed, or completely overwritten
	//
	template<addr_width::type Addr_width = addr_width::x64>
	bool flags_clobbered(dasm::routine_t<Addr_width>& routine, dasm::block_t<Addr_width>& block, dasm::inst_it_t<Addr_width> start)
	{
		xed_flag_set_t ledger;
		const xed_simple_flag_t* start_flags = XedDecodedInstGetRflagsInfo(&Start->DecodedInst);
		ledger.flat = (xed_simple_flag_get_written_flag_set(start_flags)->flat | xed_simple_flag_get_undefined_flag_set(start_flags)->flat);
		
		auto it = std::next(start);
		while (it != block.instructions.end())
		{
			const xed_simple_flag_t* inst_flag = xed_decoded_inst_get_rflags_info(&it->decoded_inst);

			if (ledger.flat & xed_simple_flag_get_read_flag_set(inst_flag)->flat)
				return FALSE;

			ledger.flat &= ~(XedSimpleFlagGetWrittenFlagSet(inst_flag)->flat | XedSimpleFlagGetUndefinedFlagSet(inst_flag)->flat);

			++it;

			if (it == block.instructions.end() && block.fallthrough_block != routine.blocks.end())
			{

			}
		}
		return TRUE;
	}

	// This does the same as above but with an arbitrary flagset
	//
	template<addr_width::type Addr_width = addr_width::x64>
	bool flags_clobbered(dasm::routine_t<Addr_width>& routine, dasm::block_t<Addr_width>& block, dasm::inst_it_t<Addr_width> start, xed_flag_set_t flagset)
	{
		
	}
}

