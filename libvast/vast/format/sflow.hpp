#ifndef VAST_FORMAT_SFLOW_HPP
#define VAST_FORMAT_SFLOW_HPP

#include <pcap.h>

#include <chrono>
#include <unordered_map>
#include <random>

#include "vast/address.hpp"
#include "vast/concept/hashable/hash_append.hpp"
#include "vast/concept/hashable/xxhash.hpp"
#include "vast/detail/operators.hpp"
#include "vast/expected.hpp"
#include "vast/port.hpp"
#include "vast/schema.hpp"
#include "vast/time.hpp"

namespace vast {

class event;

namespace format {
namespace sflow {

struct connection : detail::equality_comparable<connection> {
  address src;
  address dst;
  port sport;
  port dport;
  count mtype;
  friend bool operator==(connection const &lhs, connection const &rhs) {
    return lhs.src == rhs.src
           && lhs.dst == rhs.dst
           && lhs.sport == rhs.sport
           && lhs.dport == rhs.dport
           && lhs.mtype == rhs.mtype;;
  }
};

template<class Hasher>
void hash_append(Hasher &h, connection const &c) {
  hash_append(h, c.src, c.dst, c.sport.number(), c.dport.number(),c.mtype);
}

} // namespace sflow
} // namespace format
} // namespace vast

namespace std {

template<>
struct hash<vast::format::sflow::connection> {
  size_t operator()(vast::format::sflow::connection const &c) const {
    return vast::uhash<vast::xxhash>{}(c);
  }
};

} // namespace std

namespace vast {
namespace format {
namespace sflow {

/// A SFlow reader.
class reader {
public:
  reader() = default;

  /// Constructs a SFlow reader.
  /// @param input The name of the interface or trace file.
  /// @param cutoff The number of bytes to keep per flow.
  /// @param max_flows The maximum number of flows to keep state for.
  /// @param max_age The number of seconds to wait since the last seen packet
  ///                before evicting the corresponding flow.
  /// @param expire_interval The number of seconds between successive expire
  ///                        passes over the flow table.
  /// @param pseudo_realtime The inverse factor by which to delay packets. For
  ///                        example, if 5, then for two packets spaced *t*
  ///                        seconds apart, the source will sleep for *t/5*
  ///                        seconds.
  explicit reader(std::string input);

  ~reader();

  expected<event> read();


  expected<void> schema(vast::schema const &sch);

  expected<vast::schema> schema() const;

  const char *name() const;
private:
  struct connection_state {
    uint64_t bytes;
    uint64_t last;
  };


  std::vector<expected<event>> event_queue_;

  expected<event> read_header(const u_char *rp_header_packet,uint32_t pack_length);

  std::vector<expected<event>> read_sflow_flowsample(const u_char *fsPacket);

  std::vector<expected<event>> read_sflow_datagram(const u_char *sPacketP);


  pcap_t *pcap_ = nullptr;
  type packet_type_;



  timestamp last_timestamp_ = timestamp::min();
  int64_t pseudo_realtime_;

  std::string input_;
};

/// A PCAP writer.
class writer {
public:
  writer() = default;

  /// Constructs a PCAP writer.
  /// @param trace The path where to write the trace file.
  /// @param flush_interval The number of packets after which to flush to disk.
  writer(std::string trace, size_t flush_interval = -1);

  ~writer();

  expected<void> write(event const &e);

  expected<void> flush();

  const char *name() const;

private:
  vast::schema schema_;
  size_t flush_interval_ = 0;
  size_t total_packets_ = 0;
  pcap_t *pcap_ = nullptr;
  pcap_dumper_t *dumper_ = nullptr;
  std::string trace_;
};

} // namespace sflow
} // namespace format
} // namespace vast

#endif