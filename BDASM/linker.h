#pragma once


#include <atomic>
#include <vector>
#include <mutex>
#include <ranges>


// This file is responsible for forming links between instructions
// It does so by providing a common place for the instructions to look
// for data based on an index into a table. The basic idea is that one
// instruction sets the data in an initial placement pass, then the data
// can be read and used by other instructions in an assembly pass.
//

struct link_t
{
	uint64_t value;
};

class link_table_t
{
	std::vector<link_t> m_table;

	// Switch to a spinlock
	std::mutex m_lock;
public:
	link_table_t(uint32_t binary_size, uint32_t reserve_size = 0x1000)
	{
		m_table.reserve(binary_size + reserve_size);
		m_table.resize(binary_size);
	}

	// Locking routine to allocate a certain amount of symbols
	// returns the min and max+1 value
	//
	std::pair<uint32_t, uint32_t> get_link_bundle(uint32_t count)
	{
		std::lock_guard g(m_lock);
		uint32_t min = m_table.size();
		m_table.resize(m_table.size() + count);
		return { min, min + count};
	}

	uint32_t get_link_bundle_begin(uint32_t count)
	{
		std::lock_guard g(m_lock);
		uint32_t min = m_table.size();
		m_table.resize(m_table.size() + count);
		return min;
	}

	// The threads themselves should do this so that the table spends the least amount of time locked
	//
	//void get_link_bundle(uint32_t count, std::vector<uint32_t>& place)
	//{
	//	std::lock_guard g(m_lock);
	//	auto min = m_table.size();
	//	m_table.resize(m_table.size() + count);
	//	auto range = std::ranges::iota_view(static_cast<uint32_t>(min), static_cast<uint32_t>(m_table.size()));
	//	place.insert(place.end(), range.begin(), range.end());
	//}

	uint32_t allocate_link()
	{
		std::lock_guard g(m_lock);
		auto index = m_table.size();
		m_table.emplace_back();
		return index;
	}

	link_t& get_link(uint32_t link_index)
	{
		return m_table[link_index];
	}
};