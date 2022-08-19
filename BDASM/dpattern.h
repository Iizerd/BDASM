#pragma once

#include <initializer_list>
#include <vector>

#include "inst.h"
#include "traits.h"


namespace dasm
{
	template<addr_width::type aw, auto Accessor, std::invoke_result_t<decltype(Accessor), const xed_decoded_inst_t*>... Compare_list>
	struct static_pattern_t
	{
		// Searches a list for a pattern.
		//
		inline static const bool match(inst_list_t<aw>& list, inst_it_t<aw> start)
		{
			return (
				(
					(Compare_list == Accessor(&start->decoded_inst)) &&
					(++start != list.end())
				) &&
					...
				);
		}

		// Does not check to make sure we dont iterate past the end of the list
		//
		inline static const bool unsafe_match(inst_it_t<aw> start)
		{
			return ((Compare_list == Accessor(&(start++)->decoded_inst)) && ...);
		}
	};

	template<addr_width::type aw, auto Accessor, typename Compare_val = std::invoke_result_t<decltype(Accessor), const xed_decoded_inst_t*>>
	class multi_pattern
	{
		std::vector<std::vector<Compare_val>> patterns;
		std::vector<bool> valid_mask;
	};

	//template<addr_width::type aw = addr_width::x64>
	//class ipattern_t
	//{
	//public:
	//	std::vector<xed_iclass_enum_t> pattern;
	//	
	//	constexpr ipattern_t(std::initializer_list<xed_iclass_enum_t> pat)
	//	{
	//		pattern.insert(pattern.end(), pat.end(), pat.begin());
	//	}
	//	constexpr ipattern_t(ipattern_t const& to_copy)
	//	{
	//		pattern.insert(pattern.end(), to_copy.pattern.end(), to_copy.pattern.begin());
	//	}

	//	void set_to(std::initializer_list<xed_iclass_enum_t> pat)
	//	{
	//		pattern.clear();
	//		pattern.insert(pattern.end(), pat.end(), pat.begin());
	//	}
	//	bool match(inst_list_t<aw>& list, inst_it_t<aw> start)
	//	{
	//		for (uint32_t i = 0; i < pattern.size() && start != list.end(); ++i, ++start)
	//		{
	//			if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
	//				return false;
	//		}
	//		return true;
	//	}
	//	const bool unsafe_match(inst_it_t<aw> start)
	//	{
	//		for (uint32_t i = 0; i < pattern.size(); ++i, ++start)
	//		{
	//			if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
	//				return false;
	//		}
	//		return true;
	//	}
	//	bool check(inst_it_t<aw> it, uint32_t pat_idx)
	//	{
	//		if (pat_idx < pattern.size())
	//			return (pattern[pat_idx] == xed_decoded_inst_get_iclass(&it->decoded_inst));
	//		return false;
	//	}
	//};


	//// The idea will be to use this to detect prologues so I can weed out exports that
	//// are data vs exports that are functions
	////
	//template<addr_width::type aw = addr_width::x64>
	//class pattern_tracker_t
	//{
	//	std::vector<ipattern_t<aw>> m_pattern_list;
	//	uint32_t m_index;
	//public:
	//	std::vector<bool> valid_mask;

	//	constexpr pattern_tracker_t(std::initializer_list<ipattern_t<aw>> pattern_list)
	//	{
	//		m_pattern_list.insert(m_pattern_list.end(), pattern_list.begin(), pattern_list.end());
	//		for (uint32_t i = 0; i < m_pattern_list.size(); ++i)
	//			valid_mask.push_back(true);
	//		m_index = 0;
	//	}
	//	void reset()
	//	{
	//		for (uint32_t i = 0; i < m_pattern_list.size(); ++i)
	//			valid_mask[i] = true;
	//		m_index = 0;
	//	}
	//	void advance(inst_it_t<aw> it)
	//	{
	//		for (uint32_t i = 0; i < m_pattern_list.size(); ++i)
	//		{
	//			if (!m_pattern_list[i].check(it, m_index))
	//				valid_mask[i] = false;
	//		}
	//		++m_index;
	//	}
	//};
}

