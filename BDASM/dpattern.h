#pragma once

#include <initializer_list>
#include <vector>

#include "inst.h"
#include "traits.h"


namespace dasm
{
	template<addr_width::type Addr_width, auto Accessor, std::invoke_result_t<decltype(Accessor), const xed_decoded_inst_t*>... Compare_list>
	struct static_pattern_t
	{
		// Searches a list for a pattern.
		//
		inline static const bool match(inst_list_t<Addr_width>& list, inst_it_t<Addr_width> start)
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
		inline static const bool unsafe_match(inst_it_t<Addr_width> start)
		{
			return ((Compare_list == Accessor(&(start++)->decoded_inst)) && ...);
		}
	};

	/*template<addr_width::type Addr_width, auto Accessor, typename Compare_type = std::invoke_result_t<decltype(Accessor), const xed_decoded_inst_t*> >
	class dynamic_pattern_t
	{
		Accessor m_accessor;
		std::vector<Compare_type> m_compare_list;
		uint32_t m_index;

	public:
		constexpr dynamic_pattern_t(Accessor accessor, std::initializer_list<Compare_type> list)
			: m_accessor(accessor)
			, m_index(0)
		{
			for (auto val : list)
				m_compare_list.push_back(val);
		}

		finline reset()
		{
			m_index = 0;
		}

		bool advance(inst_it_t<Addr_width> inst_it, Compare_type compare_value)
		{
			if (m_index++ < m_compare_list.size())
				return (compare_value == m_accessor(&inst_it->decoded_inst));
			return true;
		}
		
	};


	class multi_pattern_t
	{

	};*/


	//template<addr_width::type Addr_width = addr_width::x64>
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
	//	bool match(inst_list_t<Addr_width>& list, inst_it_t<Addr_width> start)
	//	{
	//		for (uint32_t i = 0; i < pattern.size() && start != list.end(); ++i, ++start)
	//		{
	//			if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
	//				return false;
	//		}
	//		return true;
	//	}
	//	const bool unsafe_match(inst_it_t<Addr_width> start)
	//	{
	//		for (uint32_t i = 0; i < pattern.size(); ++i, ++start)
	//		{
	//			if (pattern[i] != xed_decoded_inst_get_iclass(&start->decoded_inst))
	//				return false;
	//		}
	//		return true;
	//	}
	//	bool check(inst_it_t<Addr_width> it, uint32_t pat_idx)
	//	{
	//		if (pat_idx < pattern.size())
	//			return (pattern[pat_idx] == xed_decoded_inst_get_iclass(&it->decoded_inst));
	//		return false;
	//	}
	//};


	//// The idea will be to use this to detect prologues so I can weed out exports that
	//// are data vs exports that are functions
	////
	//template<addr_width::type Addr_width = addr_width::x64>
	//class pattern_tracker_t
	//{
	//	std::vector<ipattern_t<Addr_width> > m_pattern_list;
	//	uint32_t m_index;
	//public:
	//	std::vector<bool> valid_mask;

	//	constexpr pattern_tracker_t(std::initializer_list<ipattern_t<Addr_width> > pattern_list)
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
	//	void advance(inst_it_t<Addr_width> it)
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

