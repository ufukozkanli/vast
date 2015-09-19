#ifndef VAST_CONCEPT_PARSEABLE_VAST_BGPBINARY_PARSER_H
#define VAST_CONCEPT_PARSEABLE_VAST_BGPBINARY_PARSER_H

#include <map>
#include <string>
#include <vector>
#include "vast/access.h"
#include "vast/concept/parseable/vast/address.h"

namespace vast {

//using namespace vast::util;

struct bgpbinary_parser : parser<bgpbinary_parser>
{
  struct format
  {
		time::point timestamp;
		count bgp_type;
		count type;
		count subtype;
		count interface_index;
		count addr_family;
		count old_state;
		count new_state;
		count bgp_length;
		count length;
		count pasnr;
		count med;
		count local_pref;
		std::string msg_type;
		std::string origin;
		std::string as_path_orded;
		std::string community;
		std::string atomic_aggregate;
		vast::address peer_ip_v4;
		vast::address peer_ip_v6;
		vast::address nexthop_v4;
		vast::address nexthop_v6;
		vast::vector as_path;
		vast::vector prefix_v4;
		vast::vector prefix_v6;
		std::tuple<count,vast::address> aggregator;
  };

  template <typename Iterator>
  bool parse(Iterator& f, Iterator const& l, unused_type) const
  {
		//TODO: warning unused parameter
		f = f;
		l = l;
  }

  template <typename Iterator, typename Attribute>
  format parse(Iterator& f, Iterator const& l, Attribute& a) const
  {
		using namespace parsers;

		format r;
		uint8_t t8 = 0;
		uint16_t t16 = 0;
		uint32_t t32 = 0;

		/*---------------MRT Header---------------*/
		// MRT - Timestamp
		b32be.parse(f, f + 4, t32);
		r.timestamp = time::point{time::seconds{t32}};

		// MRT - Type
		b16be.parse(f, f + 2, t16);
		r.type = count{t16};

		// MRT - Subtype
		t16 = 0;
		b16be.parse(f, f + 2, t16);
		r.subtype = count{t16};

		// MRT - Length
		t32 = 0;
	 	b32be.parse(f, f + 4,t32);
		r.length = count{t32};
		uint32_t length = t32;
		/*-------------MRT Header End-------------*/

	 	if (r.type != 16 && r.type != 17)
		{
			return {};
		}

		/*-----------BGP4MP_MESSAGE_AS4-----------*/

		// BGP4MP - Peer AS NUMBER
		t32 = 0;
	 	b32be.parse(f, f + 4,t32);
		r.pasnr = count{t32};
		length -= 4;

		// BGP4MP - Local AS NUMBER
		t32 = 0;
	 	b32be.parse(f, f + 4,t32);
		length -= 4;
		//r.lasnr = t32;

		// BGP4MP - Interface Index
		t16 = 0;
	 	b16be.parse(f, f + 2,t16);
		r.interface_index = count{t16};
		length -= 2;

		// BGP4MP - Address Family
		t16 = 0;
	 	b16be.parse(f, f + 2,t16);
		r.addr_family = t16;
		length -= 2;

		if (r.addr_family == 1)
		{
			// BGP4MP - Peer IP Address - IPv4
			t32 = 0;
			b32be.parse(f, f + 4, t32);
			r.peer_ip_v4 = address{&t32, address::ipv4, address::host};
			length -= 4;

			// BGP4MP - Local IP Address - IPv4
			f += 4;
			length -= 4;
		}

		else if (r.addr_family == 2)
		{
			// BGP4MP - Peer IP Address - IPv6
			std::array<uint8_t, 16> bytes;
			std::copy_n(f, 16, bytes.begin());
			auto bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
			r.peer_ip_v6 = address{bytes32, address::ipv6, address::network};
			length -= 16;
			f += 16;

			// BGP4MP - Local IP Address - IPV6
			f += 16;
			length -= 16;			
		}

		/*-----------BGP4MP_STATE_CHANGE-----------*/

		if (r.subtype == 0 || r.subtype == 5)
		{	 
			// BGP4MP - State - Type
			r.msg_type = "STATE";

			// BGP4MP - State - Mode 1
			t16 = 0;
			b16be.parse(f, f + 2, t16);
			r.old_state = count{t16};
			length -= 2;

			// BGP4MP - State - Mode 2
			t16 = 0;
			b16be.parse(f, f + 2, t16);
			r.new_state = count{t16};
			length -= 2;

			return r;	
		}

		/*-----------BGP4MP_STATE_CHANGE_END-----------*/

		// only BGP Message packets allowed
		if (r.subtype != 4)
		{
			return {};
		}

		// BGP - Marker
		f += 16;
		length -= 16;

		// BGP - Length
		t16 = 0;
		b16be.parse(f, f + 2, t16);
		r.bgp_length = count{t16};
		length -= 2;

		// BGP - Type
		t8 = 0;
		b8be.parse(f, f + 1, t8);
		r.bgp_type = count{t8};
		length -= 1;

		//BGP - Update only
		if (r.bgp_type != 2)
		{
			//TODO: BGP - KEEPALIVE Support
			f += length;
			return {};
		} 

		/*-----------BGP4MP_MESSAGE_UPDATE_WITHDRAW-----------*/
		// BGP - Withdraw Routes Length
		t16 = 0;
		b16be.parse(f, f + 2, t16);
		length -= 2;
		uint16_t wd_rts_len = t16;
		uint16_t wd_rts_len_bk = t16;

		// BGP - Withdraw - IPv4
		if (r.addr_family == 1 & wd_rts_len > 0)
		{
			r.msg_type = "W";
			uint8_t wd_prefix_len_v4;

			length -= wd_rts_len;
	
			// BGP - Withdraw - Length
			while (wd_rts_len > 0)
			{
				t8 = 0;
				t32 = 0;
				b8be.parse(f,f + 1, t8);
				uint8_t wd_prefix_bits = t8;
				wd_rts_len--;	
				wd_prefix_len_v4 = t8 / 8;

				if (t8 % 8 != 0)
					wd_prefix_len_v4++;

				// BGP - Withdraw - Prefix - IPv4
				for (auto i = 0; i < wd_prefix_len_v4; ++i)
				{
					t8 = 0;
					b8be.parse(f,f + 1, t8);
					t32 <<= 8;
					t32 |= t8;
					wd_rts_len--;	
				}

				for (auto i = 0; i < 4 - wd_prefix_len_v4; ++i)
					t32 <<= 8;

				r.prefix_v4.push_back(subnet{address{&t32, address::ipv4, address::host}, wd_prefix_bits});
			}
	
			if (length != 0)
			{
				f += length;
			}

			return r;

		}

		// BGP - Withdraw - IPv6
		else if (r.addr_family == 2 & wd_rts_len > 0)
		{
			r.msg_type = "W";

			uint8_t wd_prefix_len_v6;
			uint32_t const* bytes32;
			std::array<uint8_t, 16> bytes;
			address addr_v6;

			// BGP - Withdraw - Prefix - IPv6
			while (wd_rts_len > 0)
			{
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				wd_rts_len--;	
				wd_prefix_len_v6 = t8 / 8;

				if (t8 % 8 != 0)
					wd_prefix_len_v6 += 1;

				std::copy_n(f, wd_prefix_len_v6, bytes.begin());
				bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
				addr_v6 = address{bytes32, address::ipv6, address::network};
				wd_rts_len -= wd_prefix_len_v6;
				r.prefix_v6.push_back(subnet{addr_v6, t8});
			}

			length -= wd_rts_len;
			f += wd_prefix_len_v6;

			if (length != 0)
			{
				VAST_WARN("Packet-End not reached", length);
				return {};
			}
		
			return r;			
		}
		/*-----------BGP4MP_MESSAGE_UPDATE_WITHDRAW_END-----------*/	

		/*-----------BGP4MP_MESSAGE_UPDATE_ANNOUNCE---------------*/	

		// BGP - Announce - Message Type
		r.msg_type = "A";

		// BGP - Announce - Total Path Attributes Length
		t16 = 0;
		b16be.parse(f, f + 2, t16);
		length -= 2;
		uint16_t total_path_len = t16;
		uint16_t prefix_len = r.bgp_length - total_path_len - wd_rts_len_bk - 23;

		// BGP - Announce - Path Attributes & Network Layer Reachability Information not exist
		if (total_path_len == 0)
		{
			return r;
		}

		uint8_t attr_type;
		uint8_t attr_flags;
		uint16_t attr_length;

		bool attr_optional_bit;
		bool attr_transitive_bit; 
		bool attr_partial_bit;
		bool attr_ext_len_bit;
		bool attr_ignored_bit_1;
		bool attr_ignored_bit_2;
		bool attr_ignored_bit_3;
		bool attr_ignored_bit_4;
		bool attr_type_active = false;

		while (total_path_len > 0)
		{

			// BGP - Announce - Attribute Flags
			t8 = 0;
			b8be.parse(f, f + 1, t8);
			attr_flags  = t8;
			total_path_len--;
			length--;

			attr_optional_bit = static_cast<bool>((attr_flags & 128) >> 7);
			attr_transitive_bit = static_cast<bool>((attr_flags & 64) >> 6);
			attr_partial_bit = static_cast<bool>((attr_flags & 32) >> 5);
			attr_ext_len_bit = static_cast<bool>((attr_flags & 16) >> 4);
			attr_ignored_bit_1 = static_cast<bool>((attr_flags & 8) >> 3);
			attr_ignored_bit_2 = static_cast<bool>((attr_flags & 4) >> 2);
			attr_ignored_bit_3 = static_cast<bool>((attr_flags & 2) >> 1);
			attr_ignored_bit_4 = static_cast<bool>(attr_flags & 1);
		
			// BGP - Announce - Attribute Type Code (1 Byte)
			t8 = 0;
			b8be.parse(f, f + 1, t8);
			attr_type = t8;
			length--;
			total_path_len--;

			if (attr_ext_len_bit)
			{
				// BGP - Announce - Attribute Length Field (2 Bytes)
				t16 = 0;
				b16be.parse(f, f + 2, t16);
				attr_length = t16;
				total_path_len -= 2;
				length -= 2;
			}
			else
			{
				// BGP - Announce - Attribute Length Field (1 Byte)
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				attr_length = t8;
				length--;
				total_path_len--;
			}

			// BGP - Announce - Origin
			if (attr_type == 1)
			{
				while (attr_length > 0)
				{
					t8 = 0;
					b8be.parse(f, f + 1, t8);

					if (t8 == 0)
						r.origin = "IGP";

					else if (t8 == 1)
						r.origin = "EGP";

					else if (t8 == 2)
						r.origin = "INCOMPLETE";

					length--;
					total_path_len--;
					attr_length--;	
				}
			}
		
			// BGP - Announce - AS Path
			else if (attr_type == 2)
			{
				while (attr_length > 0)
				{
					// BGP - Announce - AS Path - Segment Type
					t8 = 0;
					b8be.parse(f, f + 1, t8);
					uint8_t path_seg_type = t8;

					if (path_seg_type == 1)
					{
						r.as_path_orded = "AS_SET";
						r.as_path.push_back(count{0});	
					}

					else if (path_seg_type == 2)
					{
						r.as_path_orded = "AS_SEQUENCE";
					}

					// BGP - Announce - AS Path - Segment Length (Number of AS)
					t8 = 0;
					b8be.parse(f, f + 1, t8);
					uint8_t path_seg_length = t8;

					length -= 2 + 4 * path_seg_length ;
					total_path_len -= 2 + 4 * path_seg_length;
					attr_length -= 2 + 4 * path_seg_length;

					// BGP - Announce - AS Path - Segment Value
					while (path_seg_length > 0)
					{
						t32 = 0;
						b32be.parse(f, f + 4, t32);
						r.as_path.push_back(count{t32});						
						path_seg_length--;				
					}

					if (path_seg_type == 1)
						r.as_path.push_back(count{0});	
				}
			}

			// BGP - Announce - Next Hop
			else if (attr_type == 3)
			{
				//BGP - Announce - Next Hop - IPv4
				if (r.addr_family == 1)
				{
					t32 = 0;
					b32be.parse(f, f + 4, t32);
					r.nexthop_v4 = address{&t32, address::ipv4, address::host};
					length -= 4;
					total_path_len -= 4;
					attr_length -= 4;
				}

				//BGP - Announce - Next Hop - IPv6
				else if (r.addr_family == 2)
				{
					std::array<uint8_t, 16> bytes;
					std::copy_n(f, 16, bytes.begin());
					auto bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
					r.nexthop_v6 = address{bytes32, address::ipv6, address::network};
					length -= 16;
					total_path_len -= 16;
					attr_length -= 16;
					f += 16;
				}
			}

			// BGP - Announce - Multi Exit Disc (MED)
			else if (attr_type == 4)
			{
				t32 = 0;
				b32be.parse(f, f + 4, t32);
				r.med = count{t32};
				length -= 4;
				total_path_len -= 4;
				attr_length -= 4;
			}

			// BGP - Announce - Local Pref
			else if (attr_type == 5)
			{
				t32 = 0;
				b32be.parse(f, f + 4, t32);
				r.local_pref = count{t32};
				length -= 4;
				total_path_len -= 4;
				attr_length -= 4;	
			}

			// BGP - Announce - ATOMIC AGGREGATE
			else if (attr_type == 6){}

			// BGP - Announce - AGGREGATOR
			else if (attr_type == 7)
			{
				r.atomic_aggregate = "AG";
				count aggregator_route;

				// BGP - Announce - Aggregator - Route (2 Bytes)
				if (attr_length % 6 == 0)
				{
					t16 = 0;
					b16be.parse(f, f + 2, t16);
					aggregator_route = count{t16};
					total_path_len -= 2;
					length -= 2;
					attr_length -= 2;				
				}

				// BGP - Announce - Aggregator - Route (4 Bytes)
				else if (attr_length % 8 == 0)
				{
					t32 = 0;
					b32be.parse(f, f + 4, t32);
					aggregator_route = count{t32};
					total_path_len -= 4;
					length -= 4;
					attr_length -= 4;	
				}

				// BGP - Announce - Aggregator - Prefix
				t32 = 0;
				b32be.parse(f, f + 4, t32);
				auto aggregator_addr = address{&t32, address::ipv4, address::host};
				length -= 4;
				total_path_len -= 4;
				attr_length -= 4;

	 			r.aggregator = std::make_tuple (aggregator_route, aggregator_addr); 

				if (attr_length > 0)
				{
					f += attr_length;
					total_path_len -= attr_length;
					length -= attr_length;
					attr_length = 0;	
				}
			}

			// BGP - Announce - Community (RFC 1997)
			else if (attr_type == 8)
			{
				// BGP - Announce - Community
				while (attr_length > 0)
				{
					t16 = 0;
					b16be.parse(f, f + 2, t16);
					r.community += to_string(t16);

					t16 = 0;
					b16be.parse(f, f + 2, t16);
					r.community += std::string(":") + to_string(t16) + std::string(" ");

					length -= 4;
					total_path_len -= 4;
					attr_length -= 4;
				}
				r.community.erase(r.community.end() - 1);
			}

			// BGP - Announce - MP_REACH_NLRI (RFC 2858)
			else if (attr_type == 14)
			{
				// BGP - Announce - MP_REACH_NLRI - Address Family Identifier
				t16 = 0;
				b16be.parse(f, f + 2, t16);
				//uint16_t mp_addr_family = t16;

				// BGP - Announce - MP_REACH_NLRI - Subsequent Address Family Identifier
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				//uint8_t mp_addr_family_id = t8;

				// BGP - Announce - MP_REACH_NLRI - Length of Next Hop Network Address
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				uint8_t mp_next_hop_len = t8;
				length -= (4 + mp_next_hop_len);
				total_path_len -= (4 + mp_next_hop_len);
				attr_length -= (4 + mp_next_hop_len);

				// BGP - Announce - MP_REACH_NLRI - Next Hop
				std::array<uint8_t, 16> bytes;
				std::copy_n(f, mp_next_hop_len, bytes.begin());
				auto bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
				r.nexthop_v6 = address{bytes32, address::ipv6, address::network};
				f += mp_next_hop_len;

				// BGP - Announce - MP_REACH_NLRI - SNPA
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				uint8_t mp_number_snpa = t8;
				length--;
				total_path_len--;
				attr_length--;

				if (mp_number_snpa != 0)
				{
					// TODO: SNPA Support
				}

				//BGP - Announce - MP_REACH_NLRI - Prefix IPv6
				length -= attr_length;
				total_path_len -= attr_length;

				uint8_t prefix_len_v6;
				vast::address addr_v6;

				while (attr_length > 0)
				{
					t8 = 0;
					b8be.parse(f, f + 1, t8);
					attr_length--;	
					prefix_len_v6 = t8 / 8;

					if (t8 % 8 != 0)
						prefix_len_v6 += 1;

					std::copy_n(f, prefix_len_v6, bytes.begin());
					bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
					addr_v6 = address{bytes32, address::ipv6, address::network};
					attr_length -= prefix_len_v6;
					r.prefix_v6.push_back(subnet{addr_v6, t8});
					f += prefix_len_v6;
				}

				attr_type_active = true;
			}

			// BGP - Announce - MP_UNREACH_NLRI (RFC 2858)
			else if (attr_type == 15)
			{
				//Announce Packet
				r.msg_type = "W";

				// BGP - Announce - MP_UNREACH_NLRI - Address Family Identifier
				t16 = 0;
				b16be.parse(f, f + 2, t16);
				//uint16_t mp_addr_family = t16;

				// BGP - Announce - MP_UNREACH_NLRI - Subsequent Address Family Identifier
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				//uint8_t mp_addr_family_id = t8;

				attr_length -= 3;
				total_path_len -= 3;
				length -= 3;

				//BGP - Announce - MP_UNREACH_NLRI - Prefix
				length -= attr_length;
				total_path_len -= attr_length;

				uint8_t prefix_len_v6;
				std::array<uint8_t, 16> bytes;
				uint32_t const* bytes32;
				vast::address addr_v6;

				while (attr_length > 0)
				{
					t8 = 0;
					b8be.parse(f, f + 1, t8);
					attr_length--;	
					prefix_len_v6 = t8 / 8;

					if (t8 % 8 != 0)
						prefix_len_v6 += 1;

					std::copy_n(f, prefix_len_v6, bytes.begin());
					bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
					addr_v6 = address{bytes32, address::ipv6, address::network};
					attr_length -= prefix_len_v6;
					r.prefix_v6.push_back(subnet{addr_v6, t8});
					f += prefix_len_v6;
				}

				attr_type_active = true;
			}

			// BGP - Announce - Extended Communities Attribute (RFC 4360)
			else if (attr_type == 16)
			{
				// TODO: Extended Communities support
				length -= attr_length;
				f+= attr_length;
				total_path_len -= attr_length;
			}
		}
	
		if (r.atomic_aggregate.empty())
			r.atomic_aggregate = "NAG";

		// BGP - Announce - Prefix - IPv4
		if ((r.addr_family == 1) & (!attr_type_active))
		{
			uint8_t prefix_len_v4;
			uint8_t prefix_bits;
			length -= prefix_len;

			while (prefix_len > 0)
			{
				t8 = 0;
				t32 = 0;
				b8be.parse(f,f + 1, t8);
				prefix_bits = t8;
				prefix_len_v4 = t8 / 8;
				prefix_len--;	

				if (t8 % 8 != 0)
					prefix_len_v4++;

				for (auto i = 0; i < prefix_len_v4; ++i)
				{
					t8 = 0;
					b8be.parse(f,f + 1, t8);
					t32 <<= 8;
					t32 |= t8;
					prefix_len--;	
				}

				for (auto i = 0; i < 4 - prefix_len_v4; ++i)
					t32 <<= 8;

				r.prefix_v4.push_back(subnet{address{&t32, address::ipv4, address::host}, prefix_bits});
			}
		}

		//BGP - Announce - Prefix IPv6
		else if ((r.addr_family == 2) & (!attr_type_active))
		{

			uint8_t prefix_len_v6;
			std::array<uint8_t, 16> bytes;
			uint32_t const* bytes32;
			vast::address addr_v6;

			while (prefix_len > 0)
			{
				t8 = 0;
				b8be.parse(f, f + 1, t8);
				attr_length--;	
				prefix_len_v6 = t8 / 8;

				if (t8 % 8 != 0)
					prefix_len_v6 += 1;

				std::copy_n(f, prefix_len_v6, bytes.begin());
				bytes32 = reinterpret_cast<uint32_t const*>(bytes.data());
				addr_v6 = address{bytes32, address::ipv6, address::network};
				prefix_len -= prefix_len_v6;
				r.prefix_v6.push_back(subnet{addr_v6, t8});
				f += prefix_len_v6;
			}
		}

		if (length != 0)
		{
			VAST_WARN("The Length is not zero -> there are same not interpreted fields", length);
			f = f + length;
			return {};
		}

		return r; 

		/*-----------BGP4MP_MESSAGE_UPDATE_ANNOUNCE---------------*/	
  }
};

template <>
struct parser_registry<bgpbinary_parser::format>
{
  using type = bgpbinary_parser;
};

} // namespace vast

#endif
