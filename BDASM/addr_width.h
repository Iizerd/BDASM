#pragma once

#include <cstdint>

extern "C"
{
#include <xed-interface.h>
}

enum class address_width : uint32_t
{
	x86 = 0,
	x64 = 1,
	invalid,
};

constexpr uint32_t __addr_width_table_bits[2] = { 32, 64 };
constexpr uint32_t __addr_width_table_bytes[2] = { 4, 8 };

template<address_width Addr_width>
struct addr_width_to_bytes
{
	inline constexpr static uint32_t value = __addr_width_table_bytes[static_cast<uint32_t>(Addr_width)];
};

template<address_width Addr_width>
struct addr_width_to_bits
{
	inline constexpr static uint32_t value = __addr_width_table_bits[static_cast<uint32_t>(Addr_width)];
};

template<address_width Addr_width>
struct addr_width_to_machine_state;
template<>
struct addr_width_to_machine_state<address_width::x86>
{
	inline constexpr static xed_state_t value = { XED_MACHINE_MODE_LONG_COMPAT_32, XED_ADDRESS_WIDTH_32b };
};
template<>
struct addr_width_to_machine_state<address_width::x64>
{
	inline constexpr static xed_state_t value = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
};

template<address_width Addr_width>
struct address_storage;
template<>
struct address_storage<address_width::x86> { using type = uint32_t; };
template<>
struct address_storage<address_width::x64> { using type = uint64_t; };
