#pragma once


extern "C"
{
#include <xed/xed-interface.h>
}

#include <list>

#include "traits.h"
#include "addr_width.h"

namespace dasm
{

	namespace inst_flag
	{
		typedef uint32_t type;
		constexpr type none = 0;

		// Patch types
		//
		constexpr type rel_br = (1 << 0);
		constexpr type disp = (1 << 1);
		constexpr type uses_label = (rel_br | disp);
	}

	template<address_width Addr_width = address_width::x64>
	class inst_t
	{
	public:

		inst_flag::type flags;

		// Symbol this instruction is responsible for setting the RVA of.
		//
		uint32_t my_symbol;

		// Symbol of target, used for calcuating deltas.
		//
		uint32_t used_symbol;

		// Tells the state of the following xed_decoded_inst_t
		//
		bool is_encoder_request;

		xed_decoded_inst_t decoded_inst;

		//This was for debugging
		//
		//uint32_t rva;

		explicit inst_t()
			: flags(0), 
			my_symbol(0), 
			used_symbol(0), 
			is_encoder_request(false)
		{}

		explicit inst_t(inst_t& to_copy)
			: flags(to_copy.flags), 
			my_symbol(to_copy.my_symbol), 
			used_symbol(to_copy.used_symbol), 
			is_encoder_request(0), 
			decoded_inst(to_copy.decoded_inst)
		{ }

		void zero_and_set_mode()
		{
			xed_decoded_inst_zero_set_mode(&decoded_inst, &addr_width::machine_state<Addr_width>::value);
			is_encoder_request = false;
		}

		// Initial decode routine
		//
		uint32_t decode(uint8_t* itext, uint32_t max_size)
		{
			zero_and_set_mode();

			xed_error_enum_t err = xed_decode(&decoded_inst, itext, max_size);
			if (XED_ERROR_NONE != err)
			{
				return 0;
			}

			return xed_decoded_inst_get_length(&decoded_inst);
		}

		// Redecodes the current inst to make sure it represents the most up to date settings.
		// Is there a better way to do this? Say I xed_decoded_inst_set_disp_width or something...
		// That doesnt update xed_decoded_inst_get_length;
		//
		bool redecode()
		{
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

			if (!is_encoder_request)
				xed_encoder_request_init_from_decode(&this->decoded_inst);

			uint32_t out_size = 0;
			xed_error_enum_t err = xed_encode(&this->decoded_inst, buffer, XED_MAX_INSTRUCTION_BYTES, &out_size);
			if (XED_ERROR_NONE != err)
			{
				return false;
			}

			zero_and_set_mode();

			err = xed_decode(&decoded_inst, buffer, XED_MAX_INSTRUCTION_BYTES);
			if (XED_ERROR_NONE != err)
			{
				return 0;
			}
			return true;
		}

		// Readys the inst for encoding.
		// 
		void to_encode_request()
		{
			xed_encoder_request_init_from_decode(&this->decoded_inst);
			is_encoder_request = true;
		}

		// Encode the instruction to a place, assumes enough space.
		//
		uint32_t encode(uint8_t* target)
		{
			if (!is_encoder_request)
				return 0;

			uint32_t out_size = 0;
			xed_error_enum_t err = xed_encode(&this->decoded_inst, target, XED_MAX_INSTRUCTION_BYTES, &out_size);
			if (XED_ERROR_NONE != err)
			{
				return 0;
			}
			return out_size;
		}

		uint32_t length() const
		{
			return xed_decoded_inst_get_length(&this->decoded_inst);
		}

		finline bool is_abs_mem_call()
		{
			switch (xed_decoded_inst_get_iform_enum(&this->decoded_inst))
			{
			case XED_IFORM_CALL_FAR_MEMp2:
			case XED_IFORM_CALL_NEAR_MEMv:
				return true;
			default:
				return false;
			}
		}
		finline bool is_abs_mem_jmp()
		{
			switch (xed_decoded_inst_get_iform_enum(&this->decoded_inst))
			{
			case XED_IFORM_JMP_MEMv:
			case XED_IFORM_JMP_FAR_MEMp2:
				return true;
			default:
				return false;
			}
		}
		finline bool is_rel_cond_jump()
		{
			return ((XED_CATEGORY_COND_BR == xed_decoded_inst_get_category(&this->decoded_inst)) &&
				(XED_OPERAND_RELBR == xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(&this->decoded_inst), 0))));
		}
		finline bool is_rel_uncond_jump()
		{
			return ((XED_CATEGORY_UNCOND_BR == xed_decoded_inst_get_category(&this->decoded_inst)) &&
				(XED_OPERAND_RELBR == xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(&this->decoded_inst), 0))));
		}

		finline bool is_rel_call()
		{
			auto iclass = xed_decoded_inst_get_iclass(&this->decoded_inst);
			return ((XED_ICLASS_CALL_FAR == iclass || XED_ICLASS_CALL_NEAR == iclass) &&
				(XED_OPERAND_RELBR == xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(&this->decoded_inst), 0))));
		}
		void print_details() const
		{
			std::printf("[0x%08X]\t%u\t%u\t%s\n", /*rva*/0, my_symbol, used_symbol, xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&this->decoded_inst)));
		}
	};


	template<address_width Addr_width>
	using inst_list_t = std::list<inst_t<Addr_width> >;

	template<address_width Addr_width>
	using inst_it_t = inst_list_t<Addr_width>::iterator;

	using inst32_t = inst_t<address_width::x86>;
	using inst64_t = inst_t<address_width::x64>;

	using inst_list32_t = inst_list_t<address_width::x86>;
	using inst_list64_t = inst_list_t<address_width::x64>;

	using inst_it32_t = inst_list32_t::iterator;
	using inst_it64_t = inst_list64_t::iterator;

	template<address_width Addr_width>
	uint32_t calc_inst_list_size(inst_list_t<Addr_width>const& list)
	{
		uint32_t size = 0;
		for (auto const& inst : list)
			size += inst.length();
		return size;
	}

	template<address_width Addr_width = address_width::x64>
	uint8_t* dumb_encoder(inst_list_t<Addr_width>& list, uint32_t& size)
	{
		size = calc_inst_list_size(list);

		uint8_t* res = new uint8_t[size];
		uint8_t* base = res;

		for (auto& inst : list)
		{
			inst.to_encode_request();
			auto meme = inst.encode(res);
			res += meme;
		}

		return base;
	}
}

