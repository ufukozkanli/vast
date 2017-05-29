#ifndef VAST_PORT_HPP
#define VAST_PORT_HPP

#include <cstdint>

#include "vast/detail/operators.hpp"

namespace vast {

struct access;
class json;

/// A transport-layer port.
class port : detail::totally_ordered<port> {
  friend access;

public:
  using number_type = uint16_t;

  /// The transport layer type.
  enum port_type : uint8_t { unknown, tcp, udp, icmp, cx, sctp, dccp };

  /// Constructs the empty port, i.e., @c 0/unknown.
  port() = default;

  /// Constructs a port.
  /// @param number The port number.
  /// @param type The port type.
  port(number_type number, port_type type = unknown);

  /// Retrieves the port number.
  /// @returns The port number.
  number_type number() const;

  /// Retrieves the transport protocol type.
  /// @returns The port type.
  port_type type() const;

  /// Sets the port number.
  /// @param n The new port number.
  void number(number_type n);

  /// Sets the port type.
  /// @param t The new port type.
  void type(port_type t);

  friend bool operator==(port const& x, port const& y);
  friend bool operator<(port const& x, port const& y);

  template <class Inspector>
  friend auto inspect(Inspector& f, port& p) {
    return f(p.number_, p.type_);
  }

private:
  number_type number_ = 0;
  port_type type_ = unknown;
};

bool convert(port const& p, json& j);

} // namespace vast

#endif
