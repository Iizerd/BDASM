#pragma once

extern "C"
{
#include <xed-interface.h>
}

#include "addr_width.h"

enum class register_width : uint8_t
{
	byte,
	word,
	dword,
	qword,
};

constexpr xed_reg_enum_t __reg_size_map[] = {
	XED_REG_AL, XED_REG_AX, XED_REG_EAX, XED_REG_RAX,
	XED_REG_BL, XED_REG_BX, XED_REG_EBX, XED_REG_RBX,
	XED_REG_CL, XED_REG_CX, XED_REG_ECX, XED_REG_RCX,
	XED_REG_DL, XED_REG_DX, XED_REG_EDX, XED_REG_RDX,

	XED_REG_SIL, XED_REG_SI, XED_REG_ESI, XED_REG_RSI,
	XED_REG_DIL, XED_REG_DI, XED_REG_EDI, XED_REG_RDI,
	XED_REG_BPL, XED_REG_BP, XED_REG_EBP, XED_REG_RBP,
	XED_REG_SPL, XED_REG_SP, XED_REG_ESP, XED_REG_RSP,

	XED_REG_R8B, XED_REG_R8W, XED_REG_R8D, XED_REG_R8,
	XED_REG_R9B, XED_REG_R9W, XED_REG_R9D, XED_REG_R9,
	XED_REG_R10B, XED_REG_R10W, XED_REG_R10D, XED_REG_R10,
	XED_REG_R11B, XED_REG_R11W, XED_REG_R11D, XED_REG_R11,
	XED_REG_R12B, XED_REG_R12W, XED_REG_R12D, XED_REG_R12,
	XED_REG_R13B, XED_REG_R13W, XED_REG_R13D, XED_REG_R13,
	XED_REG_R14B, XED_REG_R14W, XED_REG_R14D, XED_REG_R14,
	XED_REG_R15B, XED_REG_R15W, XED_REG_R15D, XED_REG_R15,

	XED_REG_INVALID, XED_REG_IP, XED_REG_EIP, XED_REG_RIP,
};

constexpr uint32_t __reg_enum_to_internal_id(xed_reg_enum_t reg)
{
	switch (reg)
	{
	case XED_REG_AL: case XED_REG_AX: case XED_REG_EAX: case XED_REG_RAX: return 0;
	case XED_REG_BL: case XED_REG_BX: case XED_REG_EBX: case XED_REG_RBX: return 1;
	case XED_REG_CL: case XED_REG_CX: case XED_REG_ECX: case XED_REG_RCX: return 2;
	case XED_REG_DL: case XED_REG_DX: case XED_REG_EDX: case XED_REG_RDX: return 3;

	case XED_REG_SIL: case XED_REG_SI: case XED_REG_ESI: case XED_REG_RSI: return 4;
	case XED_REG_DIL: case XED_REG_DI: case XED_REG_EDI: case XED_REG_RDI: return 5;
	case XED_REG_BPL: case XED_REG_BP: case XED_REG_EBP: case XED_REG_RBP: return 6;
	case XED_REG_SPL: case XED_REG_SP: case XED_REG_ESP: case XED_REG_RSP: return 7;

	case XED_REG_R8B: case XED_REG_R8W: case XED_REG_R8D: case XED_REG_R8: return 8;
	case XED_REG_R9B: case XED_REG_R9W: case XED_REG_R9D: case XED_REG_R9: return 9;
	case XED_REG_R10B: case XED_REG_R10W: case XED_REG_R10D: case XED_REG_R10: return 10;
	case XED_REG_R11B: case XED_REG_R11W: case XED_REG_R11D: case XED_REG_R11: return 11;
	case XED_REG_R12B: case XED_REG_R12W: case XED_REG_R12D: case XED_REG_R12: return 12;
	case XED_REG_R13B: case XED_REG_R13W: case XED_REG_R13D: case XED_REG_R13: return 13;
	case XED_REG_R14B: case XED_REG_R14W: case XED_REG_R14D: case XED_REG_R14: return 14;
	case XED_REG_R15B: case XED_REG_R15W: case XED_REG_R15D: case XED_REG_R15: return 15;

	case XED_REG_IP: case XED_REG_EIP: case XED_REG_RIP: return 16;
	default:
		return XED_REG_INVALID;
	}
}

template<xed_reg_enum_t Register_enum, register_width Register_width>
struct get_reg_as_size
{
	inline constexpr static xed_reg_enum_t value = __reg_size_map[__reg_enum_to_internal_id(Register_enum) * 4 + static_cast<uint32_t>(Register_width)];
};

template<xed_reg_enum_t Register_enum, address_width Addr_width>
struct get_max_reg_size
{
	inline constexpr static xed_reg_enum_t value = __reg_size_map[__reg_enum_to_internal_id(Register_enum) * 4 + static_cast<uint32_t>(Addr_width) + 2];
};

