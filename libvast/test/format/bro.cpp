#include <fstream>

#include "vast/concept/parseable/to.hpp"
#include "vast/concept/printable/stream.hpp"
#include "vast/concept/printable/vast/event.hpp"
#include "vast/event.hpp"
#include "vast/filesystem.hpp"

#include "vast/format/bro.hpp"

#define SUITE format
#include "test.hpp"
#include "data.hpp"

using namespace vast;
using namespace std::string_literals;

namespace {

template <typename Attribute>
bool bro_parse(type const& t, std::string const& s, Attribute& attr) {
  return format::bro::make_bro_parser<std::string::const_iterator>(t)(s, attr);
}

} // namspace <anonymous>

TEST(bro data parsing) {
  using namespace std::chrono;
  data d;
  CHECK(bro_parse(boolean_type{}, "T", d));
  CHECK(d == true);
  CHECK(bro_parse(integer_type{}, "-49329", d));
  CHECK(d == integer{-49329});
  CHECK(bro_parse(count_type{}, "49329"s, d));
  CHECK(d == count{49329});
  CHECK(bro_parse(timestamp_type{}, "1258594163.566694", d));
  auto i = duration_cast<interval>(double_seconds{1258594163.566694});
  CHECK(d == timestamp{i});
  CHECK(bro_parse(interval_type{}, "1258594163.566694", d));
  CHECK(d == i);
  CHECK(bro_parse(string_type{}, "\\x2afoo*"s, d));
  CHECK(d == "*foo*");
  CHECK(bro_parse(address_type{}, "192.168.1.103", d));
  CHECK(d == *to<address>("192.168.1.103"));
  CHECK(bro_parse(subnet_type{}, "10.0.0.0/24", d));
  CHECK(d == *to<subnet>("10.0.0.0/24"));
  CHECK(bro_parse(port_type{}, "49329", d));
  CHECK(d == port{49329, port::unknown});
  CHECK(bro_parse(vector_type{integer_type{}}, "49329", d));
  CHECK(d == vector{49329});
  CHECK(bro_parse(set_type{string_type{}}, "49329,42", d));
  CHECK(d == set{"49329", "42"});
}

TEST(bro reader/writer) {
  auto input = std::make_unique<std::ifstream>(m57_day11_18::conn);
  format::bro::reader reader{std::move(input)};
  maybe<event> e;
  std::vector<event> events;
  while (!e.error()) {
    e = reader.read();
    if (e)
      events.push_back(std::move(*e));
  }
  CHECK(e.error() == ec::end_of_input);
  REQUIRE(!events.empty());
  CHECK_EQUAL(events.size(), 8462u);
  CHECK_EQUAL(events.front().type().name(), "bro::conn");
  auto record = get_if<vector>(events.front().data());
  REQUIRE(record);
  REQUIRE_EQUAL(record->size(), 17u); // 20 columns, but 4 for the conn record
  CHECK_EQUAL(record->at(3), data{"udp"}); // one after the conn record
  CHECK_EQUAL(record->back(), data{set{}}); // table[T] is actually a set
  MESSAGE("write events back out");
  auto dir = "vast-unit-test-bro";
  format::bro::writer writer{dir};
  auto deleter = caf::detail::make_scope_guard([&] { rm(dir); });
  for (auto& e : events)
    if (!writer.write(e))
      FAIL("failed to write event");
}