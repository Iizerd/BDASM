#pragma once

#include <tuple>

#include "addr_width.h"
#include "inst.h"
#include "sdk.h"
#include "dpattern.h"

namespace obf
{
	template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
	dasm::inst_it_t<Addr_width> find_marker(dasm::inst_list_t<Addr_width>& list)
	{
		if (list.size() < BDASM_MARKER_INST_COUNT)
			return list.end();

		auto it_end = list.end();
		std::advance(it_end, -BDASM_MARKER_INST_COUNT);

	/*	for (auto it = list.begin(); it != it_end; ++it)
			if (dasm::static_pattern_t<Addr_width, 
				xed_iclass_enum_t, 
				xed_decoded_inst_get_iclass,
				XED_ICLASS_XABORT,
				XED_ICLASS_NOP,
				XED_ICLASS_XABORT,
				XED_ICLASS_XABORT>::unsafe_match(it))
				return it;*/
		for (auto it = list.begin(); it != it_end; ++it)
			if (dasm::static_pattern_t<Addr_width,
				xed_decoded_inst_get_iclass,
				XED_ICLASS_XABORT,
				XED_ICLASS_NOP,
				XED_ICLASS_XABORT,
				XED_ICLASS_XABORT>::unsafe_match(it))
				return it;


		return list.end();
	}

	template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
	uint8_t get_marker_attributes(dasm::inst_it_t<Addr_width> begin_start)
	{
		std::advance(begin_start, 2);
		return static_cast<uint8_t>(xed_decoded_inst_get_unsigned_immediate(&begin_start->decoded_inst));
	}

	//template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
	//dasm::inst_it_t<Addr_width> find_next_begin(dasm::inst_list_t<Addr_width>& list, dasm::inst_it_t<Addr_width> start)
	//{
	//	if (list.size() < BDASM_BEGIN_INST_COUNT)
	//		return list.end();

	//	for (auto it = start; it != list.end(); ++it)
	//		if (dasm::static_pattern_t<Addr_width,
	//			xed_iclass_enum_t,
	//			xed_decoded_inst_get_iclass,
	//			XED_ICLASS_XABORT,
	//			XED_ICLASS_NOP,
	//			XED_ICLASS_XABORT,
	//			XED_ICLASS_XABORT,
	//			XED_ICLASS_XABORT>::match(list, it))
	//			return it;

	//	return list.end();
	//}

	//// Search backwards for these cuz it would most likely be closer to the end...
	////
	//template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
	//dasm::inst_it_t<Addr_width> find_end_marker(dasm::inst_list_t<Addr_width>& list)
	//{
	//	if (list.size() < BDASM_END_INST_COUNT)
	//		return list.end();

	//	dasm::inst_it_t<Addr_width> it = list.end();
	//	std::advance(it, -BDASM_END_INST_COUNT);

	//	do
	//	{
	//		if (dasm::static_pattern_t<Addr_width, 
	//			xed_iclass_enum_t, 
	//			xed_decoded_inst_get_iclass,
	//			XED_ICLASS_XABORT,
	//			XED_ICLASS_NOP,
	//			XED_ICLASS_NOP,
	//			XED_ICLASS_XABORT>::unsafe_match(it))
	//			return it;

	//	} while (it-- != list.begin());

	//	return list.end();
	//}

	//// Careful with this one, no sanity checks for end of inst list. Only use this
	//// when you are 100% sure there is an end marker somewhere before the end of
	//// the instruction list.
	//// 
	//template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
	//dasm::inst_it_t<Addr_width> trace_to_end_marker(dasm::inst_it_t<Addr_width> start)
	//{
	//	while (!dasm::static_pattern_t<Addr_width, 
	//		xed_iclass_enum_t, 
	//		xed_decoded_inst_get_iclass,
	//		XED_ICLASS_XABORT,
	//		XED_ICLASS_NOP,
	//		XED_ICLASS_NOP,
	//		XED_ICLASS_XABORT>::unsafe_match(start))
	//		start = std::next(start);
	//	return start;

	//}



}
