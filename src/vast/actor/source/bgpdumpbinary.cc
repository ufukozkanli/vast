#include "vast/time.h"
#include "vast/address.h"
#include "vast/actor/source/bgpdumpbinary.h"
#include "vast/concept/parseable/numeric/binary.h"
#include "vast/concept/parseable/vast/bgpbinary_parser.h"
#include "vast/concept/printable/vast/address.h"
#include "vast/concept/printable/to_string.h"
#include "vast/concept/printable/vast/value.h"
#include "vast/concept/printable/vast/time.h"
#include "vast/concept/printable/print.h"

namespace vast {
namespace source {

bgpdumpbinary::bgpdumpbinary(std::unique_ptr<io::input_stream> is)
  : byte_based<bgpdumpbinary>{"bgpdumpbinary-source", std::move(is)}
{
  std::vector<type::record::field> fields;
  fields.emplace_back("timestamp", type::time_point{});
  fields.emplace_back("source_ip", type::address{});
  fields.emplace_back("source_as", type::count{});
  fields.emplace_back("prefix", type::subnet{});
  fields.emplace_back("as_path", type::vector{type::count{}});
  fields.emplace_back("origin_as", type::count{});
  fields.emplace_back("origin", type::string{});
  fields.emplace_back("nexthop", type::address{});
  fields.emplace_back("local_pref", type::count{});
  fields.emplace_back("med", type::count{});
  fields.emplace_back("community", type::string{});
  fields.emplace_back("atomic_aggregate", type::string{});
  fields.emplace_back("aggregator", type::string{});
  announce_type_ = type::record{fields};
  announce_type_.name("bgpdump::announcement");

  route_type_ = type::record{std::move(fields)};
  route_type_.name("bgpdump::routing");

  std::vector<type::record::field> withdraw_fields;
  withdraw_fields.emplace_back("timestamp", type::time_point{});
  withdraw_fields.emplace_back("source_ip", type::address{});
  withdraw_fields.emplace_back("source_as", type::count{});
  withdraw_fields.emplace_back("prefix", type::subnet{});
  withdraw_type_ = type::record{std::move(withdraw_fields)};
  withdraw_type_.name("bgpdump::withdrawn");

  std::vector<type::record::field> state_change_fields;
  state_change_fields.emplace_back("timestamp", type::time_point{});
  state_change_fields.emplace_back("source_ip", type::address{});
  state_change_fields.emplace_back("source_as", type::count{});
  state_change_fields.emplace_back("old_state", type::count{});
  state_change_fields.emplace_back("new_state", type::count{});
  state_change_type_ = type::record{std::move(state_change_fields)};
  state_change_type_.name("bgpdump::state_change");
}

schema bgpdumpbinary::sniff()
{
  schema sch;
  sch.add(announce_type_);
  sch.add(route_type_);
  sch.add(withdraw_type_);
  sch.add(state_change_type_);
  return sch;
}

void bgpdumpbinary::set(schema const& sch)
{
  if (auto t = sch.find_type(announce_type_.name()))
  {
    if (congruent(*t, announce_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      announce_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
  if (auto t = sch.find_type(route_type_.name()))
  {
    if (congruent(*t, route_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      route_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
  if (auto t = sch.find_type(withdraw_type_.name()))
  {
    if (congruent(*t, withdraw_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      withdraw_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
  if (auto t = sch.find_type(state_change_type_.name()))
  {
    if (congruent(*t, state_change_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      state_change_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
}

result<event> bgpdumpbinary::extract()
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
    std::tuple<count, vast::address> aggregator;
  };

  // Import the binary file once
  if (! imported_)
  {
    bytes_ = this->import();
    counter_ = bytes_.begin();
    imported_ = true;
  }

  if (counter_ == bytes_.end())
  {
    VAST_DEBUG(this, "finished import");
    done(true);
    return {};
  }

  while (! event_queue_.empty())
  {
    event current_event = event_queue_.back();
    event_queue_.pop_back();
    return std::move(current_event);
  }

  // Parse the file from the last entry until end.
  static auto p = bgpbinary_parser{};
  format fmt;
  auto x = p.parse(counter_, bytes_.end(), fmt);

  record r;

  /*----------------- Withdraw Packet ----------------*/
  auto prefix_counter = size_t{0};
  if (x.msg_type == "W")
  {
    if (x.addr_family == 1)
      prefix_counter = x.prefix_v4.size();
    else if (x.addr_family == 2)
      prefix_counter = x.prefix_v6.size();

    for (size_t i = 0; i < prefix_counter; ++i)
    {
      packet_stream_ <<"\nBGP4MP|";

      // Timestamp
      packet_stream_ << to_string(x.timestamp) << "|";
      r.emplace_back(x.timestamp);

      // Message Type
      packet_stream_ << x.msg_type << "|";

      // Withdraw - Source IPv4
      if (x.addr_family == 1)
      {
        packet_stream_ << to_string(x.peer_ip_v4) << "|";
        r.emplace_back(x.peer_ip_v4);
      }

      // Withdraw - Source IPv6
      else if (x.addr_family == 2)
      {
        packet_stream_ << to_string(x.peer_ip_v6) << "|";
        r.emplace_back(x.peer_ip_v6);
      }

      // Withdraw - AS Number
      packet_stream_ << std::dec << x.pasnr << "|";
      r.emplace_back(x.pasnr);

      // Withdraw - Prefix IPv4
      if(x.addr_family == 1)
      {
        packet_stream_ << to_string(x.prefix_v4[i]) <<"|";
        r.emplace_back(x.prefix_v4[i]);
      }

      // Withdraw - Prefix IPv6
      else if (x.addr_family == 2)
      {
        packet_stream_ << to_string(x.prefix_v6[i]) <<"|";
        r.emplace_back(x.prefix_v6[i]);
      }

      event e{{std::move(r), announce_type_}};
      e.timestamp(x.timestamp);

      if (prefix_counter == 1)
        return std::move(e);

      else
      {
        if (i == 0)
          first_event_ = e;

        else
          event_queue_.push_back(e);
      }

      packet_string_ = packet_stream_.str();
      VAST_DEBUG(this, packet_string_ << "\n");
      packet_stream_.str(std::string());
    }

    return std::move(first_event_);
  }
  /*----------------- Withdraw Packet End-------------*/

  /*----------------- State Packet -------------------*/
  else if (x.msg_type == "STATE")
  {
    packet_stream_ <<"\nBGP4MP|";

    // Timestamp
    packet_stream_ << to_string(x.timestamp) << "|";
    r.emplace_back(std::move(x.timestamp));

    // Message Type
    packet_stream_ << x.msg_type << "|";

    // State - Source IPv4
    if (x.addr_family == 1)
    {
      packet_stream_ << to_string(x.peer_ip_v4) << "|";
      r.emplace_back(std::move(x.peer_ip_v4));
    }

    // State - Source IPv6
    else if (x.addr_family == 2)
    {
      packet_stream_ << to_string(x.peer_ip_v6) << "|";
      r.emplace_back(std::move(x.peer_ip_v6));
    }

    // State - AS Number
    packet_stream_ << static_cast<int>(x.pasnr) << "|";
    r.emplace_back(std::move(x.pasnr));

    // State - Mode 1
    packet_stream_ << static_cast<int>(x.old_state) << "|";
    r.emplace_back(std::move(x.old_state));

    // State - Mode 2
    packet_stream_ << static_cast<int>(x.new_state) << "|";
    r.emplace_back(std::move(x.new_state));

    packet_string_ = packet_stream_.str();
    VAST_DEBUG(this, packet_string_ << "\n");
    packet_stream_.str(std::string());

    event e{{std::move(r), state_change_type_}};
    e.timestamp(x.timestamp);
    return std::move(e);
   }
  /*----------------- State Packet End----------------*/

  /*----------------- Announce Packet ----------------*/
  else if (x.msg_type == "A")
  {
    if (x.addr_family == 1)
    {
      prefix_counter = x.prefix_v4.size();
    }
    else if (x.addr_family == 2)
    {
      prefix_counter = x.prefix_v6.size();
    }
    else
    {
      VAST_WARN("invalid address family");
      return {};
    }

    for (size_t i = 0; i < prefix_counter; ++i)
    {
      packet_stream_ <<"\nBGP4MP|";

      // Timestamp
      packet_stream_ << to_string(x.timestamp) << "|";
      r.emplace_back(x.timestamp);

      // Message Type
      packet_stream_ << x.msg_type << "|";

      // Announce - Source IPv4
      if (x.addr_family == 1)
      {
        packet_stream_ << x.peer_ip_v4 << "|";
        r.emplace_back(x.peer_ip_v4);
      }

      // Announce - Source IPv6
      else if (x.addr_family == 2)
      {
        packet_stream_ << to_string(x.peer_ip_v6) << "|";
        r.emplace_back(x.peer_ip_v6);
      }

      // Announce - AS Number
      packet_stream_ << x.pasnr <<"|";
      r.emplace_back(x.pasnr);

      // Announce - Prefix IPv4
      if (x.addr_family == 1)
      {
        packet_stream_ << to_string(x.prefix_v4[i]) << "|";
        r.emplace_back(x.prefix_v4[i]);
      }

      // Announce - Prefix IPv6
      else if (x.addr_family == 2)
      {
        packet_stream_ << to_string(x.prefix_v6[i]) << "|";
        r.emplace_back(x.prefix_v6[i]);
      }

      // Announce - Paths
      packet_stream_ << to_string(x.as_path) << "|";
      r.emplace_back(x.as_path);

      // Announce - Origin
      packet_stream_ << x.origin << "|";
      r.emplace_back(x.origin);

      //Announce - Next Hop & Community IPv4
      if (x.addr_family == 1)
      {
        packet_stream_ << to_string(x.nexthop_v4) << "|";
        r.emplace_back(x.nexthop_v4);
      }

      //Announce - Next Hop & Community IPv6
      else if (x.addr_family == 2)
      {
        packet_stream_ << to_string(x.nexthop_v6) << "|";
        r.emplace_back(x.nexthop_v6);
      }

      // Announce - Local Pref
      packet_stream_ << x.local_pref << "|";
      r.emplace_back(x.local_pref);

      // Announce - Med
      packet_stream_ << x.med << "|";
      r.emplace_back(x.med);

      // Announce - Community
      packet_stream_ << x.community << "|";
      r.emplace_back(x.community);

      // Announce - Atomic Aggregate
      packet_stream_ << x.atomic_aggregate << "|";
      r.emplace_back(x.atomic_aggregate);

      // Announce - Aggregator
      count route;
      vast::address addr;
      std::tie(route, addr) = x.aggregator;
      packet_stream_ << "|";
      if (route != 0)
      {
        packet_stream_ << route << " " << addr << "|";
        r.emplace_back(to_string(route) + ' ' + to_string(addr));
      }

      event e{{std::move(r), announce_type_}};
      e.timestamp(x.timestamp);

      if (prefix_counter == 1)
        return std::move(e);

      if (i == 0)
        first_event_ = std::move(e);
      else
        event_queue_.push_back(std::move(e));

      packet_string_ = packet_stream_.str();
      VAST_DEBUG(this, packet_string_ << "\n");
      packet_stream_.str(std::string());
    }

    return std::move(first_event_);
    /*----------------- Announce Packet End --------------*/
  }

  return {};
}

} // namespace source
} // namespace vast
