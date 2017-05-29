#ifndef VAST_CONCEPT_PARSEABLE_VAST_PORT_HPP
#define VAST_CONCEPT_PARSEABLE_VAST_PORT_HPP

#include "vast/concept/parseable/core.hpp"
#include "vast/concept/parseable/numeric/integral.hpp"
#include "vast/port.hpp"

namespace vast {

template <>
struct access::parser<port> : vast::parser<access::parser<port>> {
  using attribute = port;

  template <typename Iterator>
  bool parse(Iterator& f, Iterator const& l, unused_type) const {
    using namespace parsers;
    auto p = u16 >> '/' >> ("?"_p | "tcp" | "udp"| "icmp"| "sctp"| "dccp"| "cx" );
    return p(f, l, unused);
  }

  template <typename Iterator>
  bool parse(Iterator& f, Iterator const& l, port& a) const {
    using namespace parsers;
    static auto p
      =  u16
      >> '/'
      >> ( "?"_p ->* [] { return port::unknown; }
         | "tcp"_p ->* [] { return port::tcp; }
         | "udp"_p ->* [] { return port::udp; }
         | "icmp"_p ->* [] { return port::icmp; }
         | "cx"_p ->* [] { return port::cx; }
         | "dccp"_p ->* [] { return port::dccp; }
         | "sctp"_p ->* [] { return port::sctp; }
         )
      ;
    return p(f, l, a.number_, a.type_);
  }
};

template <>
struct parser_registry<port> {
  using type = access::parser<port>;
};

namespace parsers {

static auto const port = make_parser<vast::port>();

} // namespace parsers

} // namespace vast

#endif
