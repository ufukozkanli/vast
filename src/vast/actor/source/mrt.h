#ifndef VAST_ACTOR_SOURCE_MRT_H
#define VAST_ACTOR_SOURCE_MRT_H

#include "vast/schema.h"
#include "vast/actor/source/base.h"

namespace vast {
namespace source {

struct mrt_state : state {
  mrt_state(local_actor* self);

  vast::schema schema() final;
  void schema(vast::schema const& sch) final;
  result<event> extract() final;

  std::vector<uint8_t> buffer;
  std::vector<event> queue;
  std::unique_ptr<std::istream> in;
  type announce_type_;
  type route_type_;
  type withdraw_type_;
  type state_change_type_;
};

/// A source reading binary
/// [MRT](https://tools.ietf.org/html/draft-ietf-grow-mrt-09) data.
/// @param self The actor handle.
/// @param in The input stream to read from.
behavior mrt(stateful_actor<mrt_state>* self,
             std::unique_ptr<std::istream> in);

} // namespace source
} // namespace vast

#endif
