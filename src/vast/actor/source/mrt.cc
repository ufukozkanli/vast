#include "vast/actor/source/mrt.h"

#include "vast/concept/parseable/core.h"
#include "vast/concept/parseable/numeric.h"
#include "vast/concept/printable/vast/type.h"
#include "vast/detail/mrt_type.h"
#include "vast/util/string.h"

namespace vast {
namespace source {

mrt_state::mrt_state(local_actor* self)
  : state{self, "mrt-source"},
    announce_type_{detail::mrt_announce_type},
    route_type_{detail::mrt_routing_type},
    withdraw_type_{detail::mrt_withdrawn_type},
    state_change_type_{detail::mrt_statechange_type} {
}

schema mrt_state::schema() {
  vast::schema sch;
  sch.add(announce_type_);
  sch.add(route_type_);
  sch.add(withdraw_type_);
  sch.add(state_change_type_);
  return sch;
}

void mrt_state::schema(vast::schema const& sch) {
  auto update = [&](type& existing) {
    if (auto proposed = sch.find(existing.name())) {
      if (congruent(*proposed, existing)) {
        VAST_VERBOSE("prefers type in schema over default type:", *proposed);
        existing = *proposed;
      } else {
        VAST_WARN("ignores incongruent schema type:", proposed->name());
      }
    }
  };
  update(announce_type_);
  update(route_type_);
  update(withdraw_type_);
  update(state_change_type_);
}

namespace {

// MRT Routing Information Type (§5)
enum mrt_type : uint16_t {
  OSPF           = 11,
  TABLE_DUMP     = 12,
  TABLE_DUMP_V2  = 13,
  BGP4MP         = 16,
  BGP4MP_ET      = 17,
  ISIS           = 32,
  ISIS_ET        = 33,
  OSPFv3         = 48,
  OSPFv3_ET      = 49
};

// BGP4MP Type (§5.4)
enum bgp4mp_subtype : uint16_t {
  BGP4MP_STATE_CHANGE = 0,
  BGP4MP_MESSAGE = 1,
  BGP4MP_STATE_CHANGE_AS4 = 4,
  BGP4MP_MESSAGE_AS4 = 5
};

// Parses an MRT message.
result<event> parse_message(time::point timestamp,
                            mrt_type type,
                            bgp4mp_subtype subtype,
                            std::vector<uint8_t> const& buffer,
                            std::vector<event>& queue) {
  event result;
  result.timestamp(timestamp);
  auto f = buffer.begin();
  auto l = buffer.end();
  switch (mrt_type t = type) {
    default:
      return {}; // Ignore unknown message types.
    case BGP4MP_ET: {
      // This Type was initially defined in the Sprint Labs Python Routing
      // Toolkit (PyRT).  It extends the MRT common header field to include a
      // 32BIT microsecond timestamp field.  The type and subtype field
      // definitions remain as defined for the BGP4MP Type.  The 32BIT
      // microsecond timestamp immediately follows the length field in the MRT
      // common header and precedes all other fields in the message.  The
      // 32BIT microsecond field is included in the computation of the length
      // field value.  The MRT common header modification is illustrated
      // below.
      //
      //      0                   1                   2                   3
      //      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //     |                           Timestamp                           |
      //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //     |             Type              |            Subtype            |
      //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //     |                             Length                            |
      //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //     |                      microsecond timestamp                    |
      //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //     |                      Message... (variable)
      //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //
      using namespace parsers;
      auto ms_ts = be32 ->* [](uint32_t x) { return time::microseconds(x); };
      time::microseconds us;
      if (!ms_ts.parse(f, l, us))
        return error{"corrupted BGP4MP_ET message"};
      result.timestamp(timestamp + us);
      // fall through
    }
    case BGP4MP: {
      // This Type was initially defined in the Zebra software package for the
      // BGP protocol with multiprotocol extension support as defined by RFC
      // 4760.  It supersedes the BGP, BGP4PLUS, BGP4PLUS_01 Types.
      switch (subtype) {
        default:
          return {}; // Ignore unknown message sub-types.
        case BGP4MP_STATE_CHANGE:
        case BGP4MP_STATE_CHANGE_AS4: {
          // TODO
          return result;
        }
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4: {
          // TODO
          return result;
        }
      }
    }
  }
}

} // namespace <anonymous>

result<event> mrt_state::extract() {
  // If we have queued events, we can return one immediately.
  if (!queue.empty()) {
    auto e = std::move(queue.back());
    queue.pop_back();
    return e;
  }
  // The spec defines a message as follows.
  //
  //    0                   1                   2                   3
  //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                           Timestamp                           |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |             Type              |            Subtype            |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                             Length                            |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                      Message... (variable)
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  // We read one event at a time from the underlying stream. To read
  // the message, we need at first read up to the length field.
  char header[3 * 4];
  in->read(header, sizeof(header));
  if (in->eof()) {
    done_ = true;
    return {};
  }
  if (in->fail())
    return error{"failure in input stream after reading MRT header"};
  time::point timestamp;
  uint16_t type;
  uint16_t subtype;
  uint32_t length;
  using namespace parsers;
  auto ts = be32 ->* [](count x) { return time::point{time::seconds{x}}; };
  auto header_parser = ts >> be16 >> be16 >> be32;
  auto t = std::tie(timestamp, type, subtype, length);
  if (! header_parser(header, t))
    return error{"could not parse MRT common header"};
  // Currently we only support BGP4MP and BGP4MP_ET.
  if (!(static_cast<mrt_type>(type) == BGP4MP
        || static_cast<mrt_type>(type) == BGP4MP_ET)) {
    in->ignore(length);
    return {};
  }
  // Read Message.
  buffer.resize(length);
  in->read(reinterpret_cast<char*>(buffer.data()), length);
  if (in->bad())
    return error{"failure in input stream after reading MRT message"};
  return parse_message(timestamp,
                       static_cast<mrt_type>(type),
                       static_cast<bgp4mp_subtype>(subtype), buffer, queue);
}

behavior mrt(stateful_actor<mrt_state>* self,
             std::unique_ptr<std::istream> in) {
  self->state.in = std::move(in);
  return make(self);
}

} // namespace source
} // namespace vast
