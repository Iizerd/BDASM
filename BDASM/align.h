#pragma once


#include <cstdint>
#include <type_traits>


template<typename Align_type>
inline Align_type align_up(Align_type val, uint32_t alignment)
{
	static_assert(std::is_integral<Align_type>::value, "Invalid parameter passed to align_up.");
	const Align_type ralign = alignment - 1;
	return static_cast<Align_type>((val + ralign) & (~ralign));
}

template<typename Align_type>
inline Align_type align_up_ptr(Align_type val, uint32_t alignment)
{
	static_assert(std::is_pointer<Align_type>::value, "Invalid parameter passed to align_up_ptr.");
	const uint64_t ralign = alignment - 1;
	return reinterpret_cast<Align_type>((reinterpret_cast<uint64_t>(val) + ralign) & (~ralign));
}

