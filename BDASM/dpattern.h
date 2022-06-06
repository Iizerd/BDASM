#pragma once

#include <initializer_list>
#include <vector>

#include "inst.h"


namespace dasm
{

	template<address_width Addr_width, xed_iclass_enum_t... IClass_list>
	class static_pattern_t
	{
	public:
		uint32_t size = sizeof...(IClass_list);
		xed_iclass_enum_t pattern[sizeof...(IClass_list)];

		constexpr static_pattern_t()
		{
			uint32_t i = 0;
			// Feels hacky...
			(
				(pattern[i++] = IClass_list),
				...
			);
		}

		const bool match(inst_list_t<Addr_width>& list, inst_it_t<Addr_width> start)
		{
			for (uint32_t i = 0; i < size && start != list.end(); ++i, ++start)
			{
				if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
					return false;
			}
			return true;
		}

		const bool unsafe_match(inst_it_t<Addr_width> start)
		{
			for (uint32_t i = 0; i < size; ++i, ++start)
			{
				if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
					return false;
			}
			return true;
		}
	};

	template<address_width Addr_width = address_width::x64>
	class pattern_t
	{
	public:
		std::vector<xed_iclass_enum_t> pattern;
		
		constexpr pattern_t(std::initializer_list<xed_iclass_enum_t> pat)
		{
			pattern.insert(pattern.end(), pat.end(), pat.begin());
		}
		constexpr pattern_t(pattern_t const& to_copy)
		{
			pattern.insert(pattern.end(), to_copy.pattern.end(), to_copy.pattern.begin());
		}

		void set_to(std::initializer_list<xed_iclass_enum_t> pat)
		{
			pattern.clear();
			pattern.insert(pattern.end(), pat.end(), pat.begin());
		}
		bool match(inst_list_t<Addr_width>& list, inst_it_t<Addr_width> start)
		{
			for (uint32_t i = 0; i < pattern.size() && start != list.end(); ++i, ++start)
			{
				if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
					return false;
			}
			return true;
		}
		const bool unsafe_match(inst_it_t<Addr_width> start)
		{
			for (uint32_t i = 0; i < pattern.size(); ++i, ++start)
			{
				if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
					return false;
			}
			return true;
		}
		bool check(inst_it_t<Addr_width> it, uint32_t pat_idx)
		{
			if (pat_idx < pattern.size())
				return (pattern[pat_idx] == xed_decoded_inst_get_iclass(&it->decoded_inst));
			return false;
		}
	};


	// The idea will be to use this to detect prologues so I can weed out exports that
	// are data vs exports that are functions
	//
	template<address_width Addr_width = address_width::x64>
	class pattern_tracker_t
	{
		std::vector<pattern_t<Addr_width> > m_pattern_list;
		uint32_t m_index;
	public:
		std::vector<bool> valid_mask;

		constexpr pattern_tracker_t(std::initializer_list<pattern_t<Addr_width> > pattern_list)
		{
			m_pattern_list.insert(m_pattern_list.end(), pattern_list.begin(), pattern_list.end());
			for (uint32_t i = 0; i < m_pattern_list.size(); ++i)
				valid_mask.push_back(true);
			m_index = 0;
		}
		void reset()
		{
			for (uint32_t i = 0; i < m_pattern_list.size(); ++i)
				valid_mask[i] = true;
			m_index = 0;
		}
		void advance(inst_it_t<Addr_width> it)
		{
			for (uint32_t i = 0; i < m_pattern_list.size(); ++i)
			{
				if (!m_pattern_list[i].check(it, m_index))
					valid_mask[i] = false;
			}
			++m_index;
		}
	};
}

