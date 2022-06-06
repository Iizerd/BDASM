#pragma once

#include <tuple>

#include "inst.h"


namespace dasm
{

	template<address_width Addr_width, xed_iclass_enum_t... IClass_list>
	class pattern_t
	{
	public:
		uint32_t size = sizeof...(IClass_list);
		xed_iclass_enum_t pattern[sizeof...(IClass_list)];

		constexpr pattern_t()
		{
			uint32_t i = 0;
			(
				(pattern[i++] = IClass_list),
				...
				);
		}

		bool apply()
		{

		}
	};



	/*template<pattern_t&... Patterns>
	class pattern_tracker_t
	{
		pattern_t& m_patterns[sizeof... Patterns];

	};*/

}

