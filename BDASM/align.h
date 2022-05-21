#pragma once


#include <cstdint>
#include <type_traits>


template<typename Align_type>
inline Align_type align_up(Align_type val, uint32_t alignment)
{
	static_assert(std::is_integral<Align_type>::value, "Invalid parameter passed to align.");
	const auto ralign = alignment - 1;
	return static_cast<Align_type>((val + ralign) & (~ralign));
}

