#pragma once

// Damn I do be pretty smart.
//

extern "C"
{
#include <xed-interface.h>
}

#include <cstdint>
#include <cstdio>
//
//
//uint8_t* __encode_encoder_inst(xed_encoder_instruction_t* enc_inst, xed_state_t machine_state)
//{
//	xed_encoder_request_t encoder_request;
//	xed_encoder_request_zero_set_mode(&encoder_request, &machine_state);
//
//	if (!xed_convert_to_encoder_request(&encoder_request, enc_inst))
//	{
//		std::printf("Failed to convert encoder inst to encoder request.\n");
//		return nullptr;
//	}
//	uint8_t* encode_buffer = new uint8_t[XED_MAX_INSTRUCTION_BYTES];
//	uint32_t out_length = 0;
//	if (auto err = xed_encode(&encoder_request, encode_buffer, XED_MAX_INSTRUCTION_BYTES, &out_length); XED_ERROR_NONE != err)
//	{
//		std::printf("Failed to encode instruction with error: %s\n", xed_error_enum_t2str(err));
//		delete[] encode_buffer;
//		return nullptr;
//	}
//	return encode_buffer;
//}
//
//template<typename... Operands, uint32_t operand_count = sizeof...(Operands)>
//uint32_t encode_inst(xed_state_t machine_state, xed_iclass_enum_t iclass, xed_uint_t effective_operand_width, Operands... operands)
//{
//	xed_encoder_instruction_t inst;
//
//#define ENCODE_IF(N) \
//    if constexpr (Operand_count == N) \
//        xed_inst##N(&inst, machine_state, iclass, effective_operand_width, operands...)
//
//	ENCODE_IF(0);
//	ENCODE_IF(1);
//	ENCODE_IF(2);
//	ENCODE_IF(3);
//	ENCODE_IF(4);
//	ENCODE_IF(5);
//	ENCODE_IF(6);
//	ENCODE_IF(7);
//
//#undef ENCODE_IF
//
//	static_assert(Operant_count <= 7, "Invalid number of operands passed to encode_instruction_in_place");
//
//	return __encode_encoder_inst(&inst, machine_state);
//}


uint32_t __encode_encoder_inst_in_place(uint8_t* place, xed_encoder_instruction_t* enc_inst, xed_state_t machine_state)
{
	xed_encoder_request_t encoder_request;
	xed_encoder_request_zero_set_mode(&encoder_request, &machine_state);

	if (!xed_convert_to_encoder_request(&encoder_request, enc_inst))
	{
		std::printf("Failed to convert encoder inst to encoder request.\n");
		return 0;
	}
	uint32_t out_length = 0;
	if (auto err = xed_encode(&encoder_request, place, XED_MAX_INSTRUCTION_BYTES, &out_length); XED_ERROR_NONE != err)
	{
		std::printf("Failed to encode instruction with error: %s\n", xed_error_enum_t2str(err));
		return 0;
	}
	return out_length;
}

template<typename... Operands, uint32_t Operand_count = sizeof...(Operands)>
uint32_t encode_inst_in_place(uint8_t* place, xed_state_t machine_state, xed_iclass_enum_t iclass, xed_uint_t effective_operand_width, Operands... operands)
{
	xed_encoder_instruction_t inst;

#define ENCODE_IF(N)					\
    if constexpr (Operand_count == N)	\
        xed_inst##N(&inst, machine_state, iclass, effective_operand_width, operands...)

	ENCODE_IF(0);
	ENCODE_IF(1);
	ENCODE_IF(2);
	ENCODE_IF(3);
	ENCODE_IF(4);
	ENCODE_IF(5);
	ENCODE_IF(6);
	ENCODE_IF(7);

#undef ENCODE_IF

	static_assert(Operand_count <= 7, "Invalid number of operands passed to encode_instruction_in_place");

	return __encode_encoder_inst_in_place(place, &inst, machine_state);
}


