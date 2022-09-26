#pragma once

/*
	NAND:
		AND A,B
		NOT A



	ADD:
		A + B == ~A - ~B

	SUB:
		A - B == ~A + ~B

	OR:
		

	NOT:
		~A == A ^ ~0
*/

#include "obf.h"

struct mba_t
{
	//template<addr_width::type aw = addr_width::x64>
	//class expression_t
	//{
	//	// Emit as instructions
	//	virtual dasm::inst_list_t<aw> emit() = 0;
	//};


	// percent_chance: 0-100 chance to mutate a possible inst
	// min_count: minimum number of instructions to mutate
	// red_space_store: store variables in unallocated stack memory
	//
	template<addr_width::type aw = addr_width::x64>
	static obf::pass_status_t pass(dasm::routine_t<aw>& routine, obf::obf_t<aw>& ctx, uint32_t percent_chance, uint32_t min_count, bool red_space_store = false)
	{

	}
};

