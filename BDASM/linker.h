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
namespace dasm
{
	struct link_t
	{
		uint64_t addr;
		link_t()
		{
			addr = 0;
		}
	};

	class linker_t
	{
		std::vector<link_t> m_table;

		// Switch to a spinlock
		std::mutex m_lock;
	public:
		static constexpr uint32_t invalid_link_value = 0xFFFFFFFF;

		linker_t(uint32_t binary_size, uint32_t reserve_size = 0x1000)
		{
			m_table.reserve(binary_size + reserve_size);
			m_table.resize(binary_size);
			for (uint32_t i = 0; i < binary_size; i++)
				m_table[i].addr = i;
		}

		// Locking routine to allocate a certain amount of symbols
		// returns the min and max+1 value
		//
		std::pair<uint32_t, uint32_t> get_link_bundle(uint32_t count)
		{
			std::lock_guard g(m_lock);
			uint32_t min = m_table.size();
			m_table.resize(m_table.size() + count);
			return { min, min + count };
		}

		uint32_t get_link_bundle_base(uint32_t count)
		{
			std::lock_guard g(m_lock);
			uint32_t min = m_table.size();
			m_table.resize(m_table.size() + count);
			return min;
		}

		uint32_t allocate_link()
		{
			std::lock_guard g(m_lock);
			auto index = m_table.size();
			m_table.emplace_back();
			return index;
		}

		uint32_t allocate_link_no_lock()
		{
			auto index = m_table.size();
			m_table.emplace_back();
			return index;
		}

		finline link_t& get_link(uint32_t link_index)
		{
			return m_table[link_index];
		}

		finline void set_link_addr(uint32_t link_index, uint64_t address)
		{
			/*if (link_index == 0)
			{
				printf("Setting 0th index to %p\n", address);
			}*/
			m_table[link_index].addr = address;
		}
		finline uint64_t get_link_addr(uint32_t link_index)
		{
			/*if (m_table[link_index].addr == 0)
			{
				printf("Accessing a 0 addr.\n");
			}*/
			return m_table[link_index].addr;
		}
	};

}
