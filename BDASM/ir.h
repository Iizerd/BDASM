#pragma once


#include <cstdio>
#include <cstdint>
#include <list>

#include "linker.h"

// Going to use the same linker scheme as dasm
//

enum class operand_type_t : uint8_t
{
	imm,
	reg,
	link,
};

enum class operand_width_t : uint8_t
{
	b8,
	b16,
	b32,
	b64,
	b128,
	b256,
	b512,
};


enum class reg_id_t : uint64_t
{
	// Instruction counter, 64 bit wide
	//
	ip,

	// Standard 64 bit gprs
	//
	r0,		r1,		r2,		r3,		r4,		r5,		r6,		r7, 
	r8,		r9,		r10,	r11,	r12,	r13,	r14,	r15,

	// rt0-7 which are needed to lift 64bit gpr using insts
	//
	rt0,	rt1,	rt2,	rt3,	rt4,	rt5,	rt6,	rt7,

	// SSE/AVX registers
	// 
	f0,		f1,		f2,		f3,		f4,		f5,		f6,		f7,
	f8,		f9,		f10,	f11,	f12,	f13,	f14,	f15,
	f16,	f17,	f18,	f19,	f20,	f21,	f22,	f23,
	f24,	f25,	f26,	f27,	f28,	f29,	f31,	f31,

	// ft0-7 which are needed to lift these larger register using insts
	//
	ft0,	ft1,	ft2,	ft3,	ft4,	ft5,		ft6,	ft7,


	// x87? O_O
};

enum class ir_class_t : uint32_t
{
	irc_nop,
	irc_mov,
	irc_ld,
	irc_st,
	irc_add,
	irc_sub,
	irc_mul,
	irc_div,
	irc_or,
	irc_and,
	irc_xor,
	irc_nand,
	irc_not,
	irc_jl,
};

// Immediates have size 8 to 64 only
//
union ir_immediate_t
{
	int8_t i8;
	int16_t i16;
	int32_t i32;
	int64_t i64;
	
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;
};

struct ir_operand
{
	operand_type_t type;
	operand_width_t width;
	uint16_t flags;				// Just a pad atm
	union
	{
		ir_immediate_t	imm;
		reg_id_t		reg;
		uint32_t		link;	// displacement/relbr
		uint64_t		raw;
	}data;
};

class ir_inst
{
	ir_class_t inst_class;
	ir_operand operands[3];

	bool validate() { return false; }
	void print() { std::printf("Instruction.\n"); }
};

class ir_block
{
	uint32_t link;
	std::list<ir_inst> insts;
};

void memes()
{
	
}

