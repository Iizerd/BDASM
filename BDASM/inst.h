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

		// Patch a 32 bit immediate with an rva inside the binary
		//
		constexpr type rva_imm32 = (1 << 2);

		// Patch a 32 bit immediate with a disp calculated like so be careful this does not calculate
		// based on rip.
		// rva - ilen + disp
		// disp = dest_link - (my_link - ilen)
		//
		constexpr type disp_imm32 = (1 << 3);

		// This is for instructions that have relocs inside of them do these even exist?
		// Seems that encoding mov rax,[64b] is valid instruction so i assume so?
		// used_link is for the rva they pointed to in the original binary
		//
		constexpr type reloc_disp = (1 << 6);	// Form:	mov		rax,[base+rva]
		constexpr type reloc_imm = (1 << 7);	// Form:	movabs	rax,base+rva

		constexpr type uses_symbol = (rel_br | disp | reloc_disp | reloc_imm);

		// This is so we know what instructions are vital for block termination
		//
		constexpr type block_terminator = (1 << 8);

		// This is for things like a ret or undetermined unconditional jumps. Pretty much
		// anything that exits/finishes the current routine.
		//
		constexpr type routine_terminator = (1 << 9);
	}

	template<addr_width::type aw = addr_width::x64>
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

			int32_t additional_disp;
		}encode_data;

		// Custom encoder called instead of the default one. decoded_inst is in encoder_inst format
		//
		std::function<uint32_t(inst_t<aw>*, pex::binary_t<aw>*, linker_t*, uint8_t*)> custom_encoder;

		// This is called after the instruction is encoded
		// Unused in favor of custom encoder now
		//
		//std::function<bool(inst_t<aw>*, uint8_t*, linker_t*, pex::binary_t<aw>*)> encode_callback;


		explicit inst_t()
			: flags(0)
			, original_rva(0)
			, my_link(linker_t::invalid_link_value)
			, used_link(linker_t::invalid_link_value)
			, is_encoder_request(false)
			, custom_encoder(nullptr)
		{
			encode_data.additional_disp = 0;
		}

		template<typename... Operands, uint32_t Operand_count = sizeof...(Operands)>
		explicit inst_t(xed_iclass_enum_t iclass, xed_uint_t effective_operand_width, Operands... operands)
			: flags(0)
			, original_rva(0)
			, my_link(linker_t::invalid_link_value)
			, used_link(linker_t::invalid_link_value)
			, is_encoder_request(false)
			, custom_encoder(nullptr)
		{
			encode_data.additional_disp = 0;

			uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

			decode(buffer, encode_inst_in_place(buffer, addr_width::machine_state<aw>::value, iclass, effective_operand_width, operands...));
		}

		explicit inst_t(inst_t const& to_copy)
			: flags(to_copy.flags)
			, my_link(to_copy.my_link)
			, used_link(to_copy.used_link)
			, is_encoder_request(to_copy.is_encoder_request)
			, decoded_inst(to_copy.decoded_inst)
			, custom_encoder(to_copy.custom_encoder)
		{
			encode_data.additional_disp = to_copy.encode_data.additional_disp;
			std::memcpy(&additional_data, &to_copy.additional_data, sizeof inst_additional_data_t);
			for (uint32_t i = 0; i < XED_MAX_INSTRUCTION_BYTES; ++i)
				encode_data.bytes[i] = to_copy.encode_data.bytes[i];
		}

		void zero_and_set_mode()
		{
			xed_decoded_inst_zero_set_mode(&decoded_inst, &addr_width::machine_state<aw>::value);
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
		finline bool resolve_deltas(pex::binary_t<aw>* binary, linker_t* linker, uint8_t* dest, uint32_t expected_length)
		{
			if (flags & inst_flag::rel_br)
			{
				int64_t ip = dest - binary->mapped_image + expected_length;
				int64_t br_disp = (int64_t)linker->get_link_addr(used_link) - ip + encode_data.additional_disp;

				xed_decoded_inst_set_branch_displacement_bits(&decoded_inst, br_disp, xed_decoded_inst_get_branch_displacement_width_bits(&decoded_inst));
			}
			else if (flags & inst_flag::disp)
			{
				int64_t ip = dest - binary->mapped_image + expected_length;
				int64_t mem_disp = (int64_t)linker->get_link_addr(used_link) - ip + encode_data.additional_disp;

				xed_decoded_inst_set_memory_displacement_bits(&decoded_inst, mem_disp, xed_decoded_inst_get_memory_displacement_width_bits(&decoded_inst, 0));
			}
			else if (flags & inst_flag::rva_imm32)
			{
				if (xed_decoded_inst_get_immediate_is_signed(&decoded_inst))
				{
					xed_decoded_inst_set_immediate_signed_bits(&decoded_inst, linker->get_link_addr(used_link) + encode_data.additional_disp, 32);
				}
				else
				{
					xed_decoded_inst_set_immediate_unsigned_bits(&decoded_inst, linker->get_link_addr(used_link) + encode_data.additional_disp, 32);
				}
			}
			else if (flags & inst_flag::reloc_disp)
			{
				/*typename addr_width::storage<aw>::type abs_addr = binary->optional_header.get_image_base() + static_cast<addr_width::storage<aw>::type>(linker->get_link_addr(used_link));
				if (!xed_patch_disp(&decoded_inst, dest, xed_disp(abs_addr, addr_width::bits<aw>::value)))
				{
					std::printf("Failed to patch reloc displacement at %X\n", dest - binary->mapped_image);
				}
				binary->remap_reloc(additional_data.reloc.original_rva, dest - binary->mapped_image + additional_data.reloc.offset_in_inst, additional_data.reloc.type);*/

				printf("reloc not supported.\n");
				return false;
			}
			else if (flags & inst_flag::reloc_imm)
			{
				/*typename addr_width::storage<aw>::type abs_addr = binary->optional_header.get_image_base() + static_cast<addr_width::storage<aw>::type>(linker->get_link_addr(used_link));
				if (!xed_patch_imm0(&decoded_inst, dest, xed_imm0(abs_addr, addr_width::bits<aw>::value)))
				{
					std::printf("Failed to patch reloc imm at %X\n", dest - binary->mapped_image);
				}
				binary->remap_reloc(additional_data.reloc.original_rva, dest - binary->mapped_image + additional_data.reloc.offset_in_inst, additional_data.reloc.type);*/

				printf("reloc not supported.\n");
				return false;
			}
			// TODO: make these^ manipulate the reloc vector inside of the binary.

			return true;
		}
		uint32_t encode_to_binary(pex::binary_t<aw>* binary, linker_t* linker, uint8_t* dest)
		{
			if (!is_encoder_request)
				to_encoder_request();

			if (custom_encoder)
				return custom_encoder(this, binary, linker, dest);

			uint32_t expected_length = length();

			if (!resolve_deltas(binary, linker, dest, expected_length))
				return 0;

			uint32_t ilen = 0;
			xed_error_enum_t err = xed_encode(&decoded_inst, dest, XED_MAX_INSTRUCTION_BYTES, &ilen);
			if (XED_ERROR_NONE != err)
			{
				return 0;
			}

			if (ilen != expected_length)
			{
				printf("Encoded inst length did not match what was expected.\n");
				return 0;
			}

			return ilen;
		}

		finline uint32_t length() const
		{
			return xed_decoded_inst_get_length(&decoded_inst);
		}

		finline uint32_t noperands() const
		{
			return xed_decoded_inst_noperands(&decoded_inst);
		}

		finline uint32_t num_explicit_operands() const
		{
			auto _inst = inst();
			auto _noperands = noperands();
			uint32_t explicit_operands = 0;
			for (uint32_t i = 0; i < _noperands; ++i)
			{
				if (XED_OPVIS_EXPLICIT == xed_operand_operand_visibility(xed_inst_operand(_inst, i)))
					++explicit_operands;
			}
			return explicit_operands;
		}

		finline const xed_inst_t* inst() const
		{
			return xed_decoded_inst_inst(&decoded_inst);
		}

		finline xed_iclass_enum_t iclass() const
		{
			return xed_decoded_inst_get_iclass(&decoded_inst);
		}

		finline xed_iform_enum_t iform() const
		{
			return xed_decoded_inst_get_iform_enum(&decoded_inst);
		}

		// I think this will always hold true...
		//
		finline uint8_t calc_reloc_offset() const
		{
			return length() - addr_width::bytes<aw>::value;
		}

		finline uint32_t effective_operand_width() const
		{
			return xed_operand_values_get_effective_operand_width(xed_decoded_inst_operands_const(&decoded_inst));
		}

		finline xed_reg_enum_t get_reg(xed_operand_enum_t operand_name) const
		{
			return xed_decoded_inst_get_reg(&decoded_inst, operand_name);
		}

		finline xed_reg_enum_t get_base_reg(uint32_t mem_idx) const
		{
			return xed_decoded_inst_get_base_reg(&decoded_inst, mem_idx);
		}

		finline xed_reg_enum_t get_index_reg(uint32_t mem_idx) const
		{
			return xed_decoded_inst_get_index_reg(&decoded_inst, mem_idx);
		}

		finline uint32_t get_scale(uint32_t mem_idx) const
		{
			return xed_decoded_inst_get_scale(&decoded_inst, mem_idx);
		}

		finline long long get_memory_displacement(uint32_t mem_idx) const
		{
			return xed_decoded_inst_get_memory_displacement(&decoded_inst, mem_idx);
		}

		finline int get_signed_immediate() const
		{
			return xed_decoded_inst_get_signed_immediate(&decoded_inst);
		}
		
		finline int get_unsigned_immediate() const
		{
			return xed_decoded_inst_get_unsigned_immediate(&decoded_inst);
		}

		finline unsigned int operand_length(uint32_t operand_idx) const
		{
			return xed_decoded_inst_operand_length(&decoded_inst, operand_idx);
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

	template<addr_width::type aw>
	using inst_list_t = std::list<inst_t<aw>>;

	template<addr_width::type aw>
	using inst_it_t = inst_list_t<aw>::iterator;

	using inst_list32_t = inst_list_t<addr_width::x86>;
	using inst_list64_t = inst_list_t<addr_width::x64>;

	using inst_it32_t = inst_list32_t::iterator;
	using inst_it64_t = inst_list64_t::iterator;

	template<addr_width::type aw>
	uint32_t calc_inst_list_size(inst_list_t<aw>const& list)
	{
		uint32_t size = 0;
		for (auto const& inst : list)
			size += inst.length();
		return size;
	}

	template<addr_width::type aw = addr_width::x64>
	uint8_t* dumb_encoder(inst_list_t<aw>& list, uint32_t& size)
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

