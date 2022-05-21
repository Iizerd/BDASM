#pragma once


extern "C"
{
#include <xed-interface.h>
}

#include "addr_width.h"
#include "inst.h"


// This just makes things easier... holy shit enum class so close to being useful,,, but then just isnt.
namespace lookup_table_entry
{
	typedef uint8_t type;

	constexpr uint8_t none = 0;

	// Is the start of an instruction
	// 
	constexpr uint8_t is_inst_start = (1 << 0);

	// Is this address inside a decoded inst.
	// 
	constexpr uint8_t is_decoded = (1 << 1);

	// This is to prevent recursive routines messing stuff up
	//
	constexpr uint8_t is_self = (1 << 2);
}


// These are NOT the commonly referred to 'basic blocks' you might find in ida graph view.
// Whenever possible, they are merged together to form single blocks of instructions that 
// occupy contiguous memory.
//
template<address_width Addr_width = address_width::x64>
class inst_block_t
{

};



