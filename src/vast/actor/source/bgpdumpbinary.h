#ifndef VAST_ACTOR_SOURCE_BGPDUMPBINARY_H
#define VAST_ACTOR_SOURCE_BGPDUMPBINARY_H

#include "vast/schema.h"
#include "vast/actor/source/byte_based.h"

namespace vast {
namespace source {

/// A source reading ASCII output from the BGPDump utility.
class bgpdumpbinary : public byte_based<bgpdumpbinary>
{
public:
  /// Spawns a BGPDump source.
  /// @param is The input stream to read BGPDump data logs from.
  bgpdumpbinary(std::unique_ptr<io::input_stream> is);

  schema sniff();

  void set(schema const& sch);

  result<event> extract();

private:
  std::stringstream packet_stream_;
  std::string packet_string_;
  std::vector<uint8_t> bytes_;
  std::vector<uint8_t>::iterator counter_;
  std::vector<event> event_queue_;
  event first_event_;
  bool imported_ = false;
  //uint8_t func_counter_ = 0;

  type announce_type_;
  type route_type_;
  type withdraw_type_;
  type state_change_type_;
};

} // namespace source
} // namespace vast

#endif
