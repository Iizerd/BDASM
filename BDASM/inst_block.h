#pragma once

#include "inst.h"



// These are NOT the commonly referred to 'basic blocks' you might find in ida graph view.
// Whenever possible, they are merged together to form single blocks of instructions that 
// occupy contiguous memory.
// The COULD be basic blocks... if divided up.
//
template<address_width Addr_width = address_width::x64>
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
	// Returns the end of the data needed to store the block
	// can do end - start to get size
	//
	uint64_t place_at(uint64_t start_address, symbol_table_t& symbol_table)
	{
		for (auto& inst : instructions)
		{
			if (inst.my_symbol)
				symbol_table.set_sym_addr_and_placed(inst.my_symbol, start_address);
			start_address += inst.length();
		}
		return start_address;
	}
	uint8_t* encode_to(uint8_t* dest, uint64_t start_address, symbol_table_t& symbol_table)
	{
		for (auto& inst : instructions)
		{
			inst.to_encode_request();
			auto ilen = inst.encode(dest);
			start_address += ilen;

			if (inst.flags & inst_flag::rel_br)
			{
				int64_t br_disp = (int64_t)symbol_table.get_symbol_by_index(inst.used_symbol).address - start_address;
				inst.decode(dest, ilen);
				if (!xed_patch_relbr(&inst.decoded_inst, dest, xed_relbr(br_disp, xed_decoded_inst_get_branch_displacement_width_bits(&inst.decoded_inst))))
				{
					std::printf("Failed to patch relative br.\n");
				}
			}
			else if (inst.flags & inst_flag::disp)
			{
				int64_t br_disp = (int64_t)symbol_table.get_symbol_by_index(inst.used_symbol).address - start_address;
				inst.decode(dest, ilen);
				if (!xed_patch_disp(&inst.decoded_inst, dest, xed_disp(br_disp, xed_decoded_inst_get_memory_displacement_width_bits(&inst.decoded_inst, 0))))
				{
					std::printf("Failed to patch displacement.\n");
				}
			}

			dest += ilen;
		}
		return dest;
	}
};