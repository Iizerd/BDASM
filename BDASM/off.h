#pragma once


// OFF = Obfuscated File Format
// 
// I call the method "blocking" which relates to the way code is broken
// up into blocks on the host/build pc. 
//

// Custom file format for partially obfuscated routines
// The goal here is to obfuscate and break a routine up into blocks that 
// are then linked to each other at runtime with absolute jumps. This is 
// done using invert jcc method for cond branches and a sort of "reloc" 
// table
//

// There is one large table of jump instructions, one for each routine that
// the original binary uses to interface with functions that have this
// technique applied to them.

#include <cstdint>

#include "addr_width.h"

#pragma pack(push, 1)

// An index within a block descriptor tells where the start of that blocks patch
// list is. The end is signified by a completely zero patch descriptor.
//
struct ff_block_patch_descriptor
{
	// An rva relative to the base of the block which is where an address needs
	// to be patched.
	//
	uint32_t rva : 14;

	// The symbol that holds the absolute address that the block needs to work
	//
	uint32_t sym_table_index : 18;

}; static_assert(sizeof(ff_block_patch_descriptor) == 4);

// Describes a block of code that can be a max size of (2^18 + 8) bytes. 
//
struct ff_block_descriptor
{
	// An rva relative to base of the image where the block lies.
	//
	uint32_t rva;
	
	// Total size of the block
	//
	uint32_t size;

	// The index into the symbol table for the symbol this block owns
	//
	uint32_t sym_table_index;

	// The base index in the patch descriptor table for this block
	//
	uint32_t patch_descriptor_base_index;
};
#pragma pack(pop)

struct ff_format_descriptor
{
	uint16_t routine_count;

	// An rva relative to the image base which points to the Block Descriptor Table,
	// an array of ff_block_descriptor structures.
	//
	uint32_t bdt_rva;

	// An rva relative to the image base which points to the Patch Descriptor Table,
	// an array of ff_block_patch_descriptor
	//
	uint32_t pdt_rva;

	// An rva relative to the image base which points to an array of unsigned integers
	// large enough to hold an address for the current: 
	//		address_storage<address_width::___>::type
	//
	uint32_t sym_table_rva;
};


// Step one will be to create mappings for the blocks so that they can
// set their respective symbols
//


template<address_width Addr_width>
struct ff_block_allocator;
template<>
struct ff_block_allocator<address_width::x86> { using type = uint32_t(*)(uint32_t); };
template<>
struct ff_block_allocator<address_width::x64> { using type = uint64_t(*)(uint32_t); };


template<address_width Addr_width, typename Addr_type = address_storage<Addr_width>::type>
void place_routines(Addr_type(*)(uint32_t) allocator)
{

}

