#include "vast/error.hpp"
#include "vast/event.hpp"

#include "vast/concept/parseable/to.hpp"
#include "vast/concept/parseable/vast/address.hpp"
#include "vast/filesystem.hpp"

#include "vast/format/sflow.hpp"

#define SUITE format

#include "test.hpp"
#include "data.hpp"
#include "vast/logger.hpp"

using namespace vast;

int debug_events(std::vector<event> &list) {

  for (auto& it : list) {

    auto pkt=get_if<vector>(it.data());
    if(pkt->size()==0)
      continue;
    auto conn_id = get_if<vector>(pkt->at(0));
    if(conn_id->size()==0)
      continue;
    auto src = get_if<address>(conn_id->at(0));
    auto dest = get_if<address>(conn_id->at(1));
    printf("\nSRC:\t");
    for (auto i=0u;i<(*src).data().size();i++) {
      if((i+1)%8==0)
        printf(" ");
      printf("%02x",(*src).data()[i]);
    }
    printf("\nDEST:\t");
    for (auto i=0u;i<(*dest).data().size();i++) {
      if((i+1)%8==0)
        printf(" ");
      printf("%02x",(*dest).data()[i]);
    }
    printf("\n");
    printf("SRC_P:%2x",get_if<port>(conn_id->at(2))->number());
    printf("\n");
    printf("SRC_D:%2x",get_if<port>(conn_id->at(3))->number());

  }
  return 0;
}


TEST (PCAPSFLOW read/write 1) {
  // Initialize a PCAP source
  format::sflow::reader reader{traces::sflow};
  auto e = expected<event>{no_error};
  std::vector<event> events;
  while (e || !e.error()) {
    e = reader.read();
    if (e)
      events.push_back(std::move(*e));
  }

  debug_events(events);
return;
  REQUIRE(!e);
  CHECK(e.error() == ec::end_of_input);
  REQUIRE(!events.empty());

  CHECK_EQUAL(events.size(), 11710U);

  CHECK_EQUAL(events[0].type().name(), "sflow::sample");
  auto pkt = get_if<vector>(events.back().data());
  REQUIRE(pkt);
  auto conn_id = get_if<vector>(pkt->at(0));
  REQUIRE(conn_id); //[192.168.1.1, 192.168.1.71, 53/udp, 64480/udp]
  auto src = get_if<address>(conn_id->at(0));
  REQUIRE(src);
  CHECK_EQUAL(*src, *to<address>("192.168.1.2"));
}
