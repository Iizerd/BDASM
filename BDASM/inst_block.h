#pragma once

#include "inst.h"

namespace dasm
{

	// These are NOT the commonly referred to 'basic blocks' you might find in ida graph view.
	// Whenever possible, they are merged together to form single blocks of instructions that 
	// occupy contiguous memory.
	// The COULD be basic blocks... if divided up.
	//
	template<addr_width::type Addr_width = addr_width::x64>
	class inst_block_t
	{
	public:
		// These are really only used when disassembling.
		//
		uint64_t start;
		uint64_t end;

		inst_list_t<Addr_width> instructions;

		explicit inst_block_t()
			: start(0), end(0)
		{}
		explicit inst_block_t(inst_block_t const& to_copy)
			: start(0), end(0)
		{
			instructions.insert(instructions.begin(), to_copy.instructions.begin(), to_copy.instructions.end());
		}
		void print_block() const
		{
			for (auto const& inst : instructions)
			{
				inst.print_details();
			}
		}
		uint32_t get_size()
		{
			uint32_t size = 0;
			for (auto const& inst : instructions)
				size += inst.length();
			return size;
		}
		// This updates the symbols for each isntruction.
		// BEWARE: make sure that the instructions the size reported by decoded_inst_get_length
		// is the actual size the instruction will be...
		//
		uint64_t place_in_binary(uint64_t start_address, symbol_table_t* symbol_table)
		{
			for (auto& inst : instructions)
			{
				if (inst.my_symbol)
					symbol_table->set_symbol_addr(inst.my_symbol, start_address);
				start_address += inst.length();
			}
			return start_address;
		}
		uint8_t* encode_to_binary(pex::binary_t<Addr_width>* binary, uint8_t* dest/*, symbol_table_t* symbol_table*/)
		{
			for (auto& inst : instructions)
			{
				dest += inst.encode_to_binary(binary, dest/*, symbol_table*/);
			}
			return dest;
		}
	};


}

