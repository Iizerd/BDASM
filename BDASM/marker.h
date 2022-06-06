#pragma once

#include <tuple>

#include "addr_width.h"
#include "inst.h"
#include "sdk.h"
#include "dpattern.h"

namespace obf
{
	template<dasm::address_width Addr_width = dasm::address_width::x64>
	dasm::inst_it_t<Addr_width> find_begin_marker(dasm::inst_list_t<Addr_width>& list)
	{
		if (list.size() < __BDASM_BEGIN_INST_COUNT)
			return list.end();

		for (auto it = list.begin(); it != list.end(); ++it)
			if (dasm::static_ipattern_t<Addr_width,
				XED_ICLASS_INT3,
				XED_ICLASS_NOP,
				XED_ICLASS_XABORT,
				XED_ICLASS_XABORT,
				XED_ICLASS_INT3>::match(list, it))
				return it;

		return list.end();
	}

	// Search backwards for these cuz it would most likely be closer to the end...
	//
	template<dasm::address_width Addr_width = dasm::address_width::x64>
	dasm::inst_it_t<Addr_width> find_end_marker(dasm::inst_list_t<Addr_width>& list)
	{
		if (list.size() < __BDASM_END_INST_COUNT)
			return list.end();

		dasm::inst_it_t<Addr_width> it = list.end();
		std::advance(it, -__BDASM_END_INST_COUNT);

		do
		{
			if (dasm::static_ipattern_t<Addr_width,
				XED_ICLASS_INT3,
				XED_ICLASS_NOP,
				XED_ICLASS_NOP,
				XED_ICLASS_INT3>::unsafe_match(it))
				return it;

		}while (it-- != list.begin())

		return list.end();
	}

	// Careful with this one, no sanity checks for end of inst list. Only use this
	// when you are 100% sure there is an end marker somewhere before the end of
	// the instruction list.
	// 
	template<dasm::address_width Addr_width = dasm::address_width::x64>
	dasm::inst_it_t<Addr_width> trace_to_end_marker(dasm::inst_it_t<Addr_width> start)
	{
		while (!dasm::static_ipattern_t<Addr_width,
			XED_ICLASS_INT3,
			XED_ICLASS_NOP,
			XED_ICLASS_NOP,
			XED_ICLASS_INT3>::unsafe_match(start))
			start = std::next(start);
		return start;
	}

	template<dasm::address_width Addr_width = dasm::address_width::x64>
	std::tuple<uint8_t, uint8_t> get_begin_data(dasm::inst_it_t<Addr_width> begin_start)
	{
		std::advance(begin_start, 2);
		return {
			xed_decoded_inst_get_unsigned_immediate(&begin_start->decoded_inst),
			xed_decoded_inst_get_unsigned_immediate(&(++begin_start)->decoded_inst)
		};
	}


}
