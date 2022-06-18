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

// This structure can be overlayed on top of a jump [eip/rip] instruction
// Both have the bytes 'ff 25 00 00 00 00'
// This is for functions inside the original binary that need to call functions
// obfuscated with OFF
//
template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
struct ff_jump_in
{
	unsigned char inst[6];
	dasm::addr_width::storage<Addr_width>::type address;
};
static_assert(sizeof(ff_jump_in<dasm::addr_width::x86>) == 10);
static_assert(sizeof(ff_jump_in<dasm::addr_width::x64>) == 14);


struct ff_jump_out
{
	unsigned char inst[5];
	uint32_t symbol_index;
}; 
static_assert(sizeof(ff_jump_out) == 9, "Invalid ff_jump_out structure");


// An index within a block descriptor tells where the start of that blocks patch
// list is. The end is signified by a completely zero patch descriptor.
//
struct ff_block_patch_descriptor
{
	// An rva relative to the base of the block which is where an address needs
	// to be patched.
	//
	uint32_t rva : 14;

	// The symbol that holds the absolute address
	//
	uint32_t symbol_index : 18;

}; 
static_assert(sizeof(ff_block_patch_descriptor) == 4);

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
	uint32_t pdt_base;

	// Jump in table index, needs to have address of entry block patched
	//
	uint32_t jit_index;
};

struct ff_routine_descriptor
{
	// Number of blocks
	//
	uint32_t block_count;
	
	// Index into bdt where this routines blocks start
	//
	uint32_t bdt_base;
};

struct ff_format_descriptor
{
	uint32_t routine_count;

	// An rva relative to the image base which points to the Routine Descriptor Table,
	// an array of ff_routine_descriptor structures.
	//
	uint32_t rdt;

	// An rva relative to the image base which points to the Block Descriptor Table,
	// an array of ff_block_descriptor structures.
	//
	uint32_t bdt;

	// An rva relative to the image base which points to the Patch Descriptor Table,
	// an array of ff_block_patch_descriptor
	//
	uint32_t pdt;

	// An rva relative to the image base which points to an array of unsigned integers
	// large enough to hold an address for the current: 
	//		address_storage<address_width::___>::type
	//
	uint32_t sym_table;

	// An rva relative to the image base which points to an array of ff_jump_in structures
	//
	uint32_t jit_base;

	// An rva relative to the image base which points to an array of ff_jump_out structures
	//
	uint32_t jot_base;
};


#pragma pack(pop)



// Step one will be to create mappings for the blocks so that they can
// set their respective symbols
//


template<dasm::addr_width::type Addr_width>
struct ff_block_allocator;
template<>
struct ff_block_allocator<dasm::addr_width::x86> { using type = uint32_t(*)(uint32_t); };
template<>
struct ff_block_allocator<dasm::addr_width::x64> { using type = uint64_t(*)(uint32_t); };


template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
void place_routines(uint8_t* image_base, ff_format_descriptor* ff_descriptor, uint64_t(*allocator)(uint32_t))
{
	// First fine all of the tables
	//

	/*ff_routine_descriptor* rdt = reinterpret_cast<ff_routine_descriptor*>(image_base + ff_descriptor->rdt);
	ff_block_descriptor* global_bdt = reinterpret_cast<ff_block_descriptor*>(image_base + ff_descriptor->bdt);
	ff_block_patch_descriptor* global_pdt = reinterpret_cast<ff_block_patch_descriptor*>(image_base + ff_descriptor->pdt);
	ff_jump_in<Addr_width>* global_jit = reinterpret_cast<ff_jump_in<Addr_width>*>(image_base + ff_descriptor->jit_base);
	ff_jump_out<Addr_width>* global_jit = reinterpret_cast<ff_jump_out<Addr_width>*>(image_base + ff_descriptor->jot_base);
	address_storage<Addr_width>* global_sym_table = reinterpret_cast<address_storage<Addr_width>*>(image_base + ff_descriptor->jit_base);

	for (uint32_t i = 0; i < ff_descriptor->routine_count; ++i)
	{

		auto bdt = &global_bdt[rdt[i].bdt_base];
		for (uint32_t j = 0; j < rdt[i].block_count; ++j)
		{
			auto alloc = allocator(bdt[j].size);
			memcpy(alloc, image_base + bdt[j].rva, bdt[j].size);
			global_sym_table[bdt[j].sym_table_index] = alloc;
		}
	}*/

}

