#pragma once


#include <list>

#include "encoder.h"
#include "traits.h"
#include "addr_width.h"
#include "symbol.h"
#include "pex.h"
#include "linker.h"

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

		// This is for instructions that have relocs inside of them do these even exist?
		// Seems that encoding mov rax,[64b] is valid instruction so i assume so?
		// used_link is for the rva they pointed to in the original binary
		//
		constexpr type reloc_disp = (1 << 2);	// Form:	mov		rax,[base+rva]
		constexpr type reloc_imm = (1 << 3);	// Form:	movabs	rax,base+rva

		constexpr type uses_symbol = (rel_br | disp | reloc_disp | reloc_imm);

		// This is so we know what instructions are vital for block termination
		//
		constexpr type block_terminator = (1 << 4);
	}

	template<addr_width::type Addr_width = addr_width::x64>
	class inst_t
	{
	public:
		inst_flag::type flags;

		// This actually has a purpose. if zero, then this was an inserted instruction and we might not want
		// to apply obfuscation techniques on it.
		//
		union
		{
			uint32_t original_rva;
			uint32_t visited;
		};

		// Link this instruction is responsible for setting the RVA of.
		//
		uint32_t my_link;

		// Link of target, used for calcuating deltas.
		//
		uint32_t used_link;

		// Tells the state of the following xed_decoded_inst_t
		//
		bool is_encoder_request;

		xed_decoded_inst_t decoded_inst;

		union inst_additional_data_t
		{
			struct reloc_data_t
			{
				uint8_t offset_in_inst;
				uint8_t type;
				uint32_t original_rva;
			}reloc;
		}additional_data;

		// Data used when encoding. Shame this has to be here. Feels hacky
		//
		struct post_encode_data_t
		{
			uint8_t bytes[XED_MAX_INSTRUCTION_BYTES];
		}encode_data;

		// This is called after the instruction is encoded
		//
		std::function<bool(inst_t<Addr_width>*, uint8_t*, linker_t*, pex::binary_t<Addr_width>*)> encode_callback;


		explicit inst_t()
			: flags(0)
			, original_rva(0)
			, my_link(0)
			, used_link(0)
			, is_encoder_request(false)
		{}

		template<typename... Operands, uint32_t Operand_count = sizeof...(Operands)>
		explicit inst_t(xed_iclass_enum_t iclass, xed_uint_t effective_operand_width, Operands... operands)
			: flags(0)
			, original_rva(0)
			, my_link(0)
			, used_link(0)
			, is_encoder_request(false)
		{
			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
			
			decode(buffer, encode_inst_in_place(buffer, addr_width::machine_state<Addr_width>::value, iclass, effective_operand_width, operands...));
		}

		explicit inst_t(inst_t const& to_copy)
			: flags(to_copy.flags) 
			, my_link(to_copy.my_link)
			, used_link(to_copy.used_link)
			, is_encoder_request(to_copy.is_encoder_request)
			, decoded_inst(to_copy.decoded_inst)
			, encode_callback(to_copy.encode_callback)
		{ 
			std::memcpy(&additional_data, &to_copy.additional_data, sizeof inst_additional_data_t);
			for (uint32_t i = 0; i < XED_MAX_INSTRUCTION_BYTES; ++i)
				encode_data.bytes[i] = to_copy.encode_data.bytes[i];
		}

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
				xed_encoder_request_init_from_decode(&decoded_inst);

			uint32_t out_size = 0;
			xed_error_enum_t err = xed_encode(&decoded_inst, buffer, XED_MAX_INSTRUCTION_BYTES, &out_size);
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
		void to_encoder_request()
		{
			xed_encoder_request_init_from_decode(&decoded_inst);
			is_encoder_request = true;
		}

		// Encode the instruction to a place, assumes enough space.
		//
		uint32_t dumb_encode(uint8_t* target)
		{
			if (!is_encoder_request)
				to_encoder_request();

			uint32_t out_size = 0;
			xed_error_enum_t err = xed_encode(&decoded_inst, target, XED_MAX_INSTRUCTION_BYTES, &out_size);
			if (XED_ERROR_NONE != err)
			{
				return 0;
			}
			return out_size;
		}
		uint32_t encode_to_binary(pex::binary_t<Addr_width>* binary, linker_t* linker, uint8_t* dest/*, bin_data_table_t* data_table*/)
		{
			if (!is_encoder_request)
				to_encoder_request();

			uint32_t ilen = 0;
			xed_error_enum_t err = xed_encode(&decoded_inst, dest, XED_MAX_INSTRUCTION_BYTES, &ilen);
			if (XED_ERROR_NONE != err)
			{
				return 0;
			}

			if (flags & inst_flag::rel_br)
			{
				int64_t ip = dest - binary->mapped_image + ilen;
				int64_t br_disp = (int64_t)linker->get_link_addr(used_link) - ip; //(int64_t)binary->data_table->get_symbol(used_link).address - ip;
				if (!xed_patch_relbr(&decoded_inst, dest, xed_relbr(br_disp, xed_decoded_inst_get_branch_displacement_width_bits(&decoded_inst))))
				{
					std::printf("Failed to patch relbr at %X\n", ip);
				}
			}
			else if (flags & inst_flag::disp)
			{
				int64_t ip = dest - binary->mapped_image + ilen;
				int64_t br_disp = (int64_t)linker->get_link_addr(used_link) - ip;
				if (!xed_patch_disp(&decoded_inst, dest, xed_disp(br_disp, xed_decoded_inst_get_memory_displacement_width_bits(&decoded_inst, 0))))
				{
					std::printf("Failed to patch displacement at %X\n", ip);
				}
			}
			if (flags & inst_flag::reloc_disp)
			{
				typename addr_width::storage<Addr_width>::type abs_addr = binary->optional_header.get_image_base() + static_cast<addr_width::storage<Addr_width>::type>(linker->get_link_addr(used_link));
				if (!xed_patch_disp(&decoded_inst, dest, xed_disp(abs_addr, addr_width::bits<Addr_width>::value)))
				{
					std::printf("Failed to patch reloc displacement at %X\n", dest - binary->mapped_image);
				}
				binary->remap_reloc(additional_data.reloc.original_rva, dest - binary->mapped_image + additional_data.reloc.offset_in_inst, additional_data.reloc.type);
			}
			else if (flags & inst_flag::reloc_imm)
			{
				typename addr_width::storage<Addr_width>::type abs_addr = binary->optional_header.get_image_base() + static_cast<addr_width::storage<Addr_width>::type>(linker->get_link_addr(used_link));
				if (!xed_patch_imm0(&decoded_inst, dest, xed_imm0(abs_addr, addr_width::bits<Addr_width>::value)))
				{
					std::printf("Failed to patch reloc imm at %X\n", dest - binary->mapped_image);
				}
				binary->remap_reloc(additional_data.reloc.original_rva, dest - binary->mapped_image + additional_data.reloc.offset_in_inst, additional_data.reloc.type);
			}
			// TODO: make these^ manipulate the reloc vector inside of the binary.

			if (encode_callback)
				encode_callback(this, dest, linker, binary);

			return ilen;
		}

		finline uint32_t length() const
		{
			return xed_decoded_inst_get_length(&decoded_inst);
		}

		// I think this will always hold true...
		//
		finline uint8_t calc_reloc_offset() const
		{
			return length() - addr_width::bytes<Addr_width>::value;
		}

		finline void common_edit(uint32_t mlink, uint32_t ulink, inst_flag::type flg)
		{
			my_link = mlink;
			used_link = ulink;
			flags |= flg;
		}

	};

	using inst32_t = inst_t<addr_width::x86>;
	using inst64_t = inst_t<addr_width::x64>;

	template<addr_width::type Addr_width>
	using inst_list_t = std::list<inst_t<Addr_width> >;

	template<addr_width::type Addr_width>
	using inst_it_t = inst_list_t<Addr_width>::iterator;

	using inst_list32_t = inst_list_t<addr_width::x86>;
	using inst_list64_t = inst_list_t<addr_width::x64>;

	using inst_it32_t = inst_list32_t::iterator;
	using inst_it64_t = inst_list64_t::iterator;

	template<addr_width::type Addr_width>
	uint32_t calc_inst_list_size(inst_list_t<Addr_width>const& list)
	{
		uint32_t size = 0;
		for (auto const& inst : list)
			size += inst.length();
		return size;
	}

	template<addr_width::type Addr_width = addr_width::x64>
	uint8_t* dumb_encoder(inst_list_t<Addr_width>& list, uint32_t& size)
	{
		size = calc_inst_list_size(list);

		uint8_t* res = new uint8_t[size];
		uint8_t* base = res;

		for (auto& inst : list)
		{
			inst.to_encoder_request();
			auto meme = inst.dumb_encode(res);
			res += meme;
		}

		return base;
	}
}

