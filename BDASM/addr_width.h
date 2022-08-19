#pragma once

#include <cstdint>

extern "C"
{
#include <xed/xed-interface.h>
}

namespace addr_width
{
	enum class type : uint32_t
	{
		__x86 = 0,
		__x64 = 1,
		__invalid,
	};

	constexpr type x86 = type::__x86;
	constexpr type x64 = type::__x64;
	constexpr type invalid = type::__invalid;

	template<type aw> struct bits;
	template<> struct bits<x86> { constexpr static uint32_t value = 32; };
	template<> struct bits<x64> { constexpr static uint32_t value = 64; };

	template<type aw> struct bytes;
	template<> struct bytes<x86> { constexpr static uint32_t value = 4; };
	template<> struct bytes<x64> { constexpr static uint32_t value = 8; };

	template<type aw> struct storage;
	template<> struct storage<x86> { using type = uint32_t; };
	template<> struct storage<x64> { using type = uint64_t; };

	template<type aw> struct machine_state;
	template<> struct machine_state<x86>
	{
		constexpr static xed_state_t value = { XED_MACHINE_MODE_LONG_COMPAT_32, XED_ADDRESS_WIDTH_32b };
	};
	template<> struct machine_state<x64>
	{
		constexpr static xed_state_t value = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
	};

	template<type aw> struct fastcall_regs;
	template<> struct fastcall_regs<x86>
	{
		constexpr static xed_reg_enum_t regs[] = { XED_REG_EDX, XED_REG_ECX };
	};
	template<> struct fastcall_regs<x64>
	{
		constexpr static xed_reg_enum_t regs[] = { XED_REG_R9, XED_REG_R8, XED_REG_RDX, XED_REG_RCX };
	};

	//template<type aw> struct gprs;
	//template<> struct gprs<x86>
	//{
	//	constexpr static xed_reg_enum_t regs[] = { XED_REG_EAX, XED_REG_RBX };
	//};
	//template<> struct gprs<x64>
	//{
	//	constexpr static xed_reg_enum_t regs[] = { XED_REG_RAX, XED_REG_RBX };
	//};

}
