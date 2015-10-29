#ifndef VAST_DETAIL_MRT_TYPE_H
#define VAST_DETAIL_MRT_TYPE_H

#include "vast/type.h"

namespace vast {
namespace detail {

inline type make_mrt_announce_type() {
  auto result = type::record{
    {"timestamp", type::time_point{}},
    {"source_ip", type::address{}},
    {"source_as", type::count{}},
    {"prefix", type::subnet{}},
    {"as_path", type::vector{type::count{}}},
    {"origin_as", type::count{}},
    {"origin", type::string{}},
    {"nexthop", type::address{}},
    {"local_pref", type::count{}},
    {"med", type::count{}},
    {"community", type::string{}},
    {"atomic_aggregate", type::string{}},
    {"aggregator", type::string{}}
  };
  result.name("mrt::announcement");
  return result;
}

inline type make_mrt_route_type() {
  auto result = type::record{
    {"timestamp", type::time_point{}},
    {"source_ip", type::address{}},
    {"source_as", type::count{}},
    {"prefix", type::subnet{}},
    {"as_path", type::vector{type::count{}}},
    {"origin_as", type::count{}},
    {"origin", type::string{}},
    {"nexthop", type::address{}},
    {"local_pref", type::count{}},
    {"med", type::count{}},
    {"community", type::string{}},
    {"atomic_aggregate", type::string{}},
    {"aggregator", type::string{}}
  };
  result.name("mrt::routing");
  return result;
}

inline type make_mrt_withdrawn_type() {
  auto result = type::record{
    {"timestamp", type::time_point{}},
    {"source_ip", type::address{}},
    {"source_as", type::count{}},
    {"prefix", type::subnet{}}
  };
  result.name("mrt::withdrawn");
  return result;
};

inline type make_mrt_statechange_type() {
  auto result = type::record{
    {"timestamp", type::time_point{}},
    {"source_ip", type::address{}},
    {"source_as", type::count{}},
    {"old_state", type::string{}},
    {"new_state", type::string{}}
  };
  result.name("mrt::state_change");
  return result;
}

type const mrt_announce_type = make_mrt_announce_type();
type const mrt_routing_type = make_mrt_route_type();
type const mrt_withdrawn_type = make_mrt_withdrawn_type();
type const mrt_statechange_type = make_mrt_statechange_type();

} // namespace detail
} // namespace vast

#endif
