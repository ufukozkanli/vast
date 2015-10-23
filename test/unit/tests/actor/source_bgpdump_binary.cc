#include "vast/actor/source/bgpdumpbinary.h"
#include "vast/concept/parseable/to.h"
#include "vast/concept/parseable/vast/address.h"
#include "vast/concept/parseable/vast/subnet.h"
#include "vast/io/file_stream.h"

#define SUITE actors
#include "test.h"
#include "data.h"

using namespace caf;
using namespace vast;

TEST(bgpdump_binary_source) {
  scoped_actor self;
  auto f = bgpdumpbinary::updates20150505;
  auto is = std::make_unique<vast::io::file_input_stream>(f);
  auto bgpdumpbinary = self->spawn<source::bgpdumpbinary>(std::move(is));
  self->monitor(bgpdumpbinary);
  anon_send(bgpdumpbinary, put_atom::value, sink_atom::value, self);
  self->receive([&](upstream_atom, actor const& a) { CHECK(a == bgpdumpbinary); });

  MESSAGE("running the source");
  anon_send(bgpdumpbinary, run_atom::value);
  MESSAGE("source finished");
  self->receive(
    [&](std::vector<event> const& events) {
      //REQUIRE(events.size() == 11782);
      MESSAGE("in test");
      CHECK(events[0].type().name() == "bgpdump::announcement");  
      auto r = get<record>(events[0]);
      REQUIRE(r);
      CHECK((*r)[1] == *to<address>("12.0.1.63"));
      CHECK((*r)[2] == 7018);
      CHECK((*r)[3] == *to<subnet>("200.29.8.0/24"));
      auto as_path = get<vector>((*r)[4]);
      CHECK(as_path->size() == 3);
      CHECK((*as_path)[0] == 7018);
      CHECK((*as_path)[1] == 6762);
      CHECK((*as_path)[2] == 14318);

      CHECK(events[13].type().name() == "bgpdump::withdrawn");
      r = get<record>(events[13]);
      REQUIRE(r);
      CHECK((*r)[1] == *to<address>("12.0.1.63"));
      CHECK((*r)[2] == 7018);
      CHECK((*r)[3] == *to<subnet>("200.29.8.0/24"));

      CHECK(events[73].type().name() == "bgpdump::state_change");
      r = get<record>(events[73]);
      REQUIRE(r);
      CHECK((*r)[1] == *to<address>("111.91.233.1"));
      CHECK((*r)[2] == 45896);
      CHECK((*r)[3] == 3);
      CHECK((*r)[4] == 2);
    }
  );
  // The source terminates after having read the entire log file.
  self->receive(
    [&](down_msg const& d) { CHECK(d.reason == exit::done); }
  );
  self->await_all_other_actors_done();
}
