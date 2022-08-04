#pragma once


extern "C"
{
#include <xed/xed-interface.h>
}

#include <cstdint>

enum xed_condition_code_t : uint8_t
{
	XED_CC_B,
	XED_CC_BE,
	XED_CC_L,
	XED_CC_LE,
	XED_CC_NB,
	XED_CC_NBE,
	XED_CC_NL,
	XED_CC_NLE,
	XED_CC_NO,
	XED_CC_NP,
	XED_CC_NS,
	XED_CC_NZ,
	XED_CC_O,
	XED_CC_P,
	XED_CC_S,
	XED_CC_Z,
	XED_CC_COMPAT_END, //Everything before this has jcc and cmovcc versions
	XED_CC_CXZ,
	XED_CC_ECXZ,
	XED_CC_RCXZ,
	XED_CC_INVALID,
};

xed_condition_code_t __cc_inversion_map[] = {
	XED_CC_NB,
	XED_CC_NBE,
	XED_CC_NL,
	XED_CC_NLE,
	XED_CC_B,
	XED_CC_BE,
	XED_CC_L,
	XED_CC_LE,
	XED_CC_O,
	XED_CC_P,
	XED_CC_S,
	XED_CC_Z,
	XED_CC_NO,
	XED_CC_NP,
	XED_CC_NS,
	XED_CC_NZ,
	XED_CC_INVALID,
	XED_CC_INVALID,
	XED_CC_INVALID,
	XED_CC_INVALID,
	XED_CC_INVALID,
};

xed_iclass_enum_t __cc_cmovcc_map[] = {
	XED_ICLASS_CMOVB,
	XED_ICLASS_CMOVBE,
	XED_ICLASS_CMOVL,
	XED_ICLASS_CMOVLE,
	XED_ICLASS_CMOVNB,
	XED_ICLASS_CMOVNBE,
	XED_ICLASS_CMOVNL,
	XED_ICLASS_CMOVNLE,
	XED_ICLASS_CMOVNO,
	XED_ICLASS_CMOVNP,
	XED_ICLASS_CMOVNS,
	XED_ICLASS_CMOVNZ,
	XED_ICLASS_CMOVO,
	XED_ICLASS_CMOVP,
	XED_ICLASS_CMOVS,
	XED_ICLASS_CMOVZ,
	XED_ICLASS_INVALID,
	XED_ICLASS_INVALID,
	XED_ICLASS_INVALID,
	XED_ICLASS_INVALID,
	XED_ICLASS_INVALID,
};

xed_iclass_enum_t __cc_jcc_map[] = {
	XED_ICLASS_JB,
	XED_ICLASS_JBE,
	XED_ICLASS_JL,
	XED_ICLASS_JLE,
	XED_ICLASS_JNB,
	XED_ICLASS_JNBE,
	XED_ICLASS_JNL,
	XED_ICLASS_JNLE,
	XED_ICLASS_JNO,
	XED_ICLASS_JNP,
	XED_ICLASS_JNS,
	XED_ICLASS_JNZ,
	XED_ICLASS_JO,
	XED_ICLASS_JP,
	XED_ICLASS_JS,
	XED_ICLASS_JZ,
	XED_ICLASS_INVALID,
	XED_ICLASS_JCXZ,
	XED_ICLASS_JECXZ,
	XED_ICLASS_JRCXZ,
	XED_ICLASS_INVALID,
};

bool __cc_supports_cmovcc[] = {
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	false,
	false,
	false,
	false,
	false,
};

bool __cc_supports_jcc[] = {
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	true,
	false,
	true,
	true,
	true,
	false,
};

constexpr bool xed_condition_code_supports_cmovcc(xed_condition_code_t cc)
{
	return __cc_supports_cmovcc[cc];
}

constexpr bool xed_condition_code_supports_jcc(xed_condition_code_t cc)
{
	return __cc_supports_jcc[cc];
}

constexpr xed_condition_code_t xed_invert_condition_code(xed_condition_code_t cc)
{
	return __cc_inversion_map[cc];
}

constexpr bool xed_condition_code_is_convertible(xed_condition_code_t cc)
{
	return (xed_condition_code_supports_cmovcc(cc) && xed_condition_code_supports_jcc(cc));
}

constexpr xed_iclass_enum_t xed_condition_code_to_cmovcc(xed_condition_code_t cc)
{
	return __cc_cmovcc_map[cc];
}

constexpr xed_iclass_enum_t xed_condition_code_to_jcc(xed_condition_code_t cc)
{
	return __cc_jcc_map[cc];
}

constexpr xed_condition_code_t xed_iclass_to_condition_code(xed_iclass_enum_t iclass)
{
	switch (iclass)
	{
	case XED_ICLASS_JB: [[fallthrough]]; case XED_ICLASS_CMOVB: return XED_CC_B;
	case XED_ICLASS_JBE: [[fallthrough]]; case XED_ICLASS_CMOVBE: return XED_CC_BE;
	case XED_ICLASS_JL: [[fallthrough]]; case XED_ICLASS_CMOVL: return XED_CC_L;
	case XED_ICLASS_JLE: [[fallthrough]]; case XED_ICLASS_CMOVLE: return XED_CC_LE;
	case XED_ICLASS_JNB: [[fallthrough]]; case XED_ICLASS_CMOVNB: return XED_CC_NB;
	case XED_ICLASS_JNBE: [[fallthrough]]; case XED_ICLASS_CMOVNBE: return XED_CC_NBE;
	case XED_ICLASS_JNL: [[fallthrough]]; case XED_ICLASS_CMOVNL: return XED_CC_NL;
	case XED_ICLASS_JNLE: [[fallthrough]]; case XED_ICLASS_CMOVNLE: return XED_CC_NLE;
	case XED_ICLASS_JNO: [[fallthrough]]; case XED_ICLASS_CMOVNO: return XED_CC_NO;
	case XED_ICLASS_JNP: [[fallthrough]]; case XED_ICLASS_CMOVNP: return XED_CC_NP;
	case XED_ICLASS_JNS: [[fallthrough]]; case XED_ICLASS_CMOVNS: return XED_CC_NS;
	case XED_ICLASS_JNZ: [[fallthrough]]; case XED_ICLASS_CMOVNZ: return XED_CC_NZ;
	case XED_ICLASS_JO: [[fallthrough]]; case XED_ICLASS_CMOVO: return XED_CC_O;
	case XED_ICLASS_JP: [[fallthrough]]; case XED_ICLASS_CMOVP: return XED_CC_P;
	case XED_ICLASS_JS: [[fallthrough]]; case XED_ICLASS_CMOVS: return XED_CC_S;
	case XED_ICLASS_JZ: [[fallthrough]]; case XED_ICLASS_CMOVZ: return XED_CC_Z;
	case XED_ICLASS_JCXZ: return XED_CC_CXZ;
	case XED_ICLASS_JECXZ: return XED_CC_ECXZ;
	case XED_ICLASS_JRCXZ: return XED_CC_RCXZ;
	default: return XED_CC_INVALID;
	}
}
