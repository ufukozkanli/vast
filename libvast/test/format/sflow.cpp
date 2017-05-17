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

int tdebugEvents(std::vector<event> &list) {

  //or (std::vector<event>::iterator it = list.begin(); it != list.end(); ++it) {
  for (auto& it : list) {
    auto pkt=get_if<vector>(it.data());
    auto conn_id = get_if<vector>(pkt->at(0));
    //continue;
    auto src = get_if<address>(conn_id->at(1));
    printf("\n");
    for (int i=0;i<(*src).data().size();i++) {
      printf(" %02x ",(*src).data()[i]);
    }

    //printf("%02x\n",*src);//,a->data()->at(1),it->data()->at(2),it->data()->at(3));
//    struct in_addr ipS, ipD;
//    ipS.s_addr = it->data()->at(0) ->IpAddressS;
//    ipD.s_addr = it->IpAddressD;
//
//    fprintf(fp,"\n###PACKET:%d Event:%d####\n"
//                   "TcpPortS:%d\n"
//                   "TcpPortP:%d\n"
//                   "IdAddressS:%s\n"
//                   "IdAddressP:%s\n"
//                   "\n", it->PacketNumber, ++i, it->TcpPortS, it->TcpPortD, inet_ntoa(ipS), inet_ntoa(ipD)
//    );
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

  //tdebugEvents(events);

          REQUIRE(!e);
          CHECK(e.error() == ec::end_of_input);
          REQUIRE(!events.empty());
  std::cout << "events.size:" << events.size() << std::endl;
          CHECK_EQUAL(events.size(), 5855);
          CHECK_EQUAL(events[0].type().name(), "sflow::sample");
  auto pkt = get_if<vector>(events.back().data());
          REQUIRE(pkt);
  auto conn_id = get_if<vector>(pkt->at(0));
          REQUIRE(conn_id); //[192.168.1.1, 192.168.1.71, 53/udp, 64480/udp]
  auto src = get_if<address>(conn_id->at(0));
          REQUIRE(src);
  //CHECK_EQUAL(*src, *to<address>("192.168.1.1"));
//            MESSAGE("write out read packets");
//    auto file = "vast-unit-test-sflow.pcap";
//    format::sflow::writer writer{file};
//    auto deleter = caf::detail::make_scope_guard([&] { rm(file); });
//    for (auto& e : events)
//                REQUIRE(writer.write(e));
}
