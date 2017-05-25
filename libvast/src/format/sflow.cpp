#include <netinet/in.h>

#include <thread>

#include "vast/error.hpp"
#include "vast/event.hpp"
#include "vast/filesystem.hpp"
#include "vast/logger.hpp"

#include "vast/format/sflow.hpp"

#include "vast/detail/assert.hpp"
#include "vast/detail/byte_swap.hpp"


#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <vector>

#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define SFLOWFILEPRINTTYPE 3
FILE *fp = stdout;//fopen ( "pcapTestResult.txt", "w" ) ;
FILE *fp_e = stdout;//fopen ( "pcapTestResultEvents.txt", "w" ) ;
#define debug_print(type, ...)\
  do { if (type==0 && SFLOWFILEPRINTTYPE<=type) fprintf(fp, __VA_ARGS__); else if(type==1 && SFLOWFILEPRINTTYPE<=type) fprintf(fp_e, __VA_ARGS__);else if(type>2 && SFLOWFILEPRINTTYPE<=type) fprintf(stdout,__VA_ARGS__); } while (0)

namespace vast {
namespace format {
namespace sflow {
namespace {

inline type make_packet_type() {
  auto packet = record_type{
          {"meta", record_type{
                  {"src",   address_type{}},
                  {"dst",   address_type{}},
                  {"sport", port_type{}},
                  {"dport", port_type{}}}},
          {"data", string_type{}.attributes({{"skip"}})}
  };
  packet.name("sflow::sample");
  return packet;
}

static auto const pcap_packet_type = make_packet_type();

} // namespace <anonymous>



reader::reader(std::string input)
        : packet_type_{pcap_packet_type},
          input_{std::move(input)} {
}

reader::~reader() {
  if (pcap_)
    ::pcap_close(pcap_);
}


expected<event> reader::read() {
  //TODO Return events on demand (lazy loading)
  // return previous sflow samples
   if (!event_queue_.empty()) {
    auto evt = std::move(event_queue_.front());
    event_queue_.erase(event_queue_.begin());


    return evt;
  }

  char buf[PCAP_ERRBUF_SIZE]; // for errors.
  if (!pcap_) {
    if (input_ != "-" && !exists(input_))
      return make_error(ec::format_error, "no such file: ", input_);
#ifdef PCAP_TSTAMP_PRECISION_NANO
    pcap_ = ::pcap_open_offline_with_tstamp_precision(
            input_.c_str(), PCAP_TSTAMP_PRECISION_NANO, buf);
#else
    pcap_ = ::pcap_open_offline(input_.c_str(), buf);
#endif
    if (!pcap_) {
      return make_error(ec::format_error, "failed to open pcap file ",
                        input_, ": ", std::string{buf});
    }
    VAST_INFO(name(), "reads trace from", input_);
  }

  uint8_t const *data;
  pcap_pkthdr *header;
  auto r = ::pcap_next_ex(pcap_, &header, &data);
  if (r == 0)
    return no_error; // Attempt to fetch next packet timed out.
  if (r == -2) {
    return make_error(ec::end_of_input, "reached end of trace");
  }
  if (r == -1) {
    auto err = std::string{::pcap_geterr(pcap_)};
    ::pcap_close(pcap_);
    pcap_ = nullptr;
    return make_error(ec::format_error, "failed to get next packet: ", err);
  }

  // Parse packet.
  auto packet_size = header->len - 14;
  auto layer3 = data + 14;
  uint8_t const *layer4 = nullptr;
  uint8_t layer4_proto = 0;
  auto layer2_type = *reinterpret_cast<uint16_t const *>(data + 12);
  uint64_t payload_size = packet_size;
  switch (detail::to_host_order(layer2_type)) {
    default:
      return no_error; // Skip all non-IP packets.
    case 0x0800: {
      if (header->len < 14 + 20)
        return make_error(ec::format_error, "IPv4 header too short");
      size_t header_size = (*layer3 & 0x0f) * 4;
      if (header_size < 20)
        return make_error(ec::format_error, "IPv4 header too short: ",
                          header_size, " bytes");
      //auto orig_h = reinterpret_cast<uint32_t const *>(layer3 + 12);
      //auto resp_h = reinterpret_cast<uint32_t const *>(layer3 + 16);
      //conn.src = {orig_h, address::ipv4, address::network};
      //conn.dst = {resp_h, address::ipv4, address::network};
      layer4_proto = *(layer3 + 9);
      layer4 = layer3 + header_size;
      payload_size -= header_size;
    }
      break;
    case 0x86dd: {
      if (header->len < 14 + 40)
        return make_error(ec::format_error, "IPv6 header too short");
      //auto orig_h = reinterpret_cast<uint32_t const *>(layer3 + 8);
      //auto resp_h = reinterpret_cast<uint32_t const *>(layer3 + 24);
      //conn.src = {orig_h, address::ipv4, address::network};
      //conn.dst = {resp_h, address::ipv4, address::network};
      layer4_proto = *(layer3 + 6);
      layer4 = layer3 + 40;
      payload_size -= 40;
    }
      break;
  }
  if (layer4_proto == IPPROTO_UDP) {
    VAST_ASSERT(layer4);
    auto orig_p = *reinterpret_cast<uint16_t const *>(layer4);
    auto resp_p = *reinterpret_cast<uint16_t const *>(layer4 + 2);
    orig_p = detail::to_host_order(orig_p);
    resp_p = detail::to_host_order(resp_p);
    //conn.sport = {orig_p, port::udp};
    //conn.dport = {resp_p, port::udp};
    payload_size -= 8;
    //LAYER 5 SFLOW
    //Parse SFlow
    uint8_t const *layer5 = nullptr;

    layer5 = layer4 + 8;
    int static pc=0;
    pc++;
    VAST_DEBUG("PC:",pc);

    auto events_header = read_sflow_datagram(layer5);
    event_queue_.insert(event_queue_.end(), events_header.begin(), events_header.end());

  }
  return no_error;
}


expected<event> reader::read_header(const u_char *rp_header_packet, uint32_t pack_length) {
  //TODO Create Single Function both sflow samples and pcap samples (SIMILAR FUNCTION IN PCAP HEADER READER)
  //current_event = {};
  connection conn;

  debug_print(1, KMAG
          "\n\t\t\t\t###Ethernet Record");

  auto layer2_type = detail::to_host_order(*reinterpret_cast<uint16_t const *>(rp_header_packet + 12));
  debug_print(1, "\n"
          "\t\t\t\tlayer2_type:\t%02x\n", layer2_type
  );
  auto layer3 = rp_header_packet + 14;
  const u_char *layer4;
  u_char layer4_proto;
  //Check IPv4 or IPv6
  switch (layer2_type) {
    default: {
      debug_print(1, "Format:0x%02x Expected format (IPv4(0x800) or IPv6(0x86dd))\n", layer2_type);
      return no_error;
    }
    case 0x0800: {
      //IPv4
      size_t header_size = (*layer3 & 0x0f) * 4;
      layer4_proto = *(layer3 + 9);
      layer4 = layer3 + header_size;
      auto orig_h = reinterpret_cast<uint32_t const *>(layer3 + 12);
      auto resp_h = reinterpret_cast<uint32_t const *>(layer3 + 16);

//      struct in_addr ipS, ipD;
//      ipS.s_addr = orig_h;
//      ipD.s_addr = resp_h;
//      debug_print(1, "\n"
//              "\t\t\t\t\tips:\t%s\n"
//              "\t\t\t\t\tipD:\t%s\n", inet_ntoa(ipS), inet_ntoa(ipD)
//      );
      conn.src = {orig_h, address::ipv4, address::network};
      conn.dst = {resp_h, address::ipv4, address::network};
      //current_event.ip_address_s = *orig_h;
      //current_event.ip_address_d = *resp_h;
    }
      break;
    case 0x86dd: {
//IPv6
      layer4_proto = *(layer3 + 6);
      layer4 = layer3 + 40;
      //TODO 128 IPv6
      auto orig_h = reinterpret_cast<uint32_t const *>(layer3 + 8);
      auto resp_h = reinterpret_cast<uint32_t const *>(layer3 + 24);
      conn.src = {orig_h, address::ipv4, address::network};
      conn.dst = {resp_h, address::ipv4, address::network};
      //current_event.ip_address_s = *orig_h;
      //current_event.ip_address_d = *resp_h;
    }
      break;
  }

  //current_event.type = layer4_proto;
  if (layer4_proto == IPPROTO_TCP) {
    auto orig_p = detail::to_host_order(*reinterpret_cast<uint16_t const *>(layer4));
    auto resp_p = detail::to_host_order(*reinterpret_cast<uint16_t const *>(layer4 + 2));
    conn.sport = {orig_p, port::tcp};
    conn.dport = {resp_p, port::tcp};
    //current_event.port_s = orig_p;
    //current_event.port_d = resp_p;
  } else if (layer4_proto == IPPROTO_UDP) {
    auto orig_p = detail::to_host_order(*reinterpret_cast<uint16_t const *>(layer4));
    auto resp_p = detail::to_host_order(*reinterpret_cast<uint16_t const *>(layer4 + 2));
    conn.sport = {orig_p, port::udp};
    conn.dport = {resp_p, port::udp};
    //current_event.port_s = orig_p;
    //current_event.port_d = resp_p;
  } else if (layer4_proto == IPPROTO_ICMP) {
    auto message_type = *reinterpret_cast<uint8_t const *>(layer4);
    auto message_code = *reinterpret_cast<uint8_t const *>(layer4 + 1);
    conn.sport = {message_type, port::icmp};
    conn.dport = {message_code, port::icmp};
    //current_event.port_s = message_type;
    //current_event.port_d = message_code;
  } else {
    debug_print(1, "\n0x%02xExpected TCP,UDP and ICMP  implemented..\n", layer4_proto);
    return no_error;
  }

//  struct in_addr ipS, ipD;
//  ipS.s_addr = current_event.ip_address_s;
//  ipD.s_addr = current_event.ip_address_d;
//
//  debug_print(1, "\n###PACKET:?Event:%d####\n"
//          "PortS:%d\n"
//          "PortP:%d\n"
//          "IdAddressS:%s\n"
//          "IdAddressP:%s\n"
//          "\n",  0, current_event.port_s, current_event.port_d, inet_ntoa(ipS),
//              inet_ntoa(ipD)
//  );



  vector sf_packet;
  vector meta;
  meta.emplace_back(std::move(conn.src));
  meta.emplace_back(std::move(conn.dst));
  meta.emplace_back(std::move(conn.sport));
  meta.emplace_back(std::move(conn.dport));
  sf_packet.emplace_back(std::move(meta));
  auto str = reinterpret_cast<char const *>(rp_header_packet + 14);
  sf_packet.emplace_back(std::string{str, pack_length - 14});
  event e{{std::move(sf_packet), packet_type_}};
  e.timestamp(timestamp::clock::now());

  //event_queue_.push_back(std::move(e));

  return e;
}

std::vector<expected<event>> reader::read_sflow_flowsample(const u_char *fs_packet) {
  //Number Of Flow Records
  auto fs_flow_record = detail::to_host_order(*reinterpret_cast<uint32_t const *>(fs_packet + 28));
  debug_print(1, "\n"
          "\t\tsFS_FlowRecord:\t%02x\n", fs_flow_record
  );
  //Points to First Flow Records
  const u_char *fs_frecord_packet = fs_packet + 32;
  std::vector<expected<event>> sample_queue_;
  for (int i = 0; i < static_cast<int>(fs_flow_record); i++) {
    //
    debug_print(1, KCYN
            "\n\t\t\t###Flow Record:%d", i + 1);

    auto fr_data_format = detail::to_host_order(*reinterpret_cast<uint32_t const *>(fs_frecord_packet));
    auto fr_format = fr_data_format & 0X00000FFF;
    auto fr_flow_data_length = detail::to_host_order(*reinterpret_cast<uint32_t const *>(fs_frecord_packet + 4));

    auto fs_flow_data = fs_frecord_packet + 8;
    //Check Flow Data Format
    // 1=Raw Packet Header
    // 2=Ethernet Frame
    // 3=IPv4
    // 4=IPv6
    // 1001=Extended Switch Data
    // 1002=Extended Router Data
    if (fr_format == 1) {
      //Raw Packet Header
      auto fs_raw_header_protocol = detail::to_host_order(*reinterpret_cast<uint32_t const *>(fs_flow_data));
      auto fs_raw_header_size = detail::to_host_order(*reinterpret_cast<uint32_t const *>(fs_flow_data + 12));
      debug_print(1, "\n"
              "\t\t\tsFS_RP_FormatV:\t\t\t%02x\n"
              "\t\t\tsFS_RP_FlowDataLength:\t\t%02x\n"
              "\t\t\tsFS_RP_OriginalPacketLength:\t%02x\n"
              "\t\t\tsFS_RP_HeaderProtocol:\t\t%02x\n", fr_format, fr_flow_data_length,
                  fs_raw_header_size, fs_raw_header_protocol
      );
      //Check Header Protocol
      //ETHERNET-ISO88023    = 1,
      //ISO88024-TOKENBUS    = 2,
      //ISO88025-TOKENRING   = 3,
      //FDDI                 = 4,
      //FRAME-RELAY          = 5,
      //X25                  = 6,
      //PPP                  = 7,
      //SMDS                 = 8,
      //AAL5                 = 9,
      //AAL5-IP              = 10, /* e.g. Cisco AAL5 mux */
      //IPv4                 = 11,
      //IPv6                 = 12,
      //MPLS                 = 13,
      //POS                  = 14  /* RFC 1662, 2615 */
      if (fs_raw_header_protocol == 1) {
        //###Ethernet Frame Data:
        //TODO HeaderSize checking
        auto sample_c = read_header(fs_flow_data + 16, fs_raw_header_size);
        sample_queue_.push_back(sample_c);
      } else {
        debug_print(1, "Not implemented..FS->FR->HeaderProtocol\n");
      }
    } else {
      debug_print(1, "Not implemented..FS->RP->Format\n");
    }
    //Point to next Flow Record(Previous poiner+length of data + 8bits header info)
    fs_frecord_packet = fs_frecord_packet + fr_flow_data_length + 8;

    debug_print(1, KCYN
            "\t\t\t###Flow Record:%d END###\n"
            KWHT, i + 1);

  }
  return sample_queue_;
}

std::vector<expected<event>> reader::read_sflow_datagram(const u_char *s_packet) {
  std::vector<expected<event>> sflow_s_queue_;
  //CHECK IF UDP PACKET IS  SFLOW
  auto datagram_ver = detail::to_host_order(*reinterpret_cast<uint32_t const *>(s_packet));
  if (!(datagram_ver == 2 || datagram_ver == 4 || datagram_ver == 5)) {
    debug_print(1, "Sflow Version Expected:2,4,5..\n");
    return sflow_s_queue_;
  }
  auto s_address_type = detail::to_host_order(*reinterpret_cast<uint32_t const *>(s_packet + 4));

  int ip_length = 0;
  //Agent Address IPV4 ? if agent address is V4 skip 4 bytes V6 skip  16 bytes
  if (s_address_type == 1) {
    ip_length = 4;
  } else if (s_address_type == 2) {
    ip_length = 16;
  } else {
    debug_print(1, "Sflow IP Header Problem..\n");
    //auto err = std::string{::pcap_geterr(pcap_)};
    //return make_error(ec::format_error, "failed to get next packet: ", err);
    return sflow_s_queue_;
  }
  //TOTAL Number of SFLOW Samples
  auto num_samples = detail::to_host_order(*reinterpret_cast<uint32_t const *>(s_packet + ip_length + 20));

  debug_print(1, "\n--\n"
          "sDatagramVersionV:\t%02x\n"
          "sAddressTypeV:\t\t%02x\n"
          "sNumSamplesV:\t\t%02X\n"
          "\n", datagram_ver, s_address_type, num_samples
  );

  //FOR EACH SFLOW Samples
  //points to first sample packet
  const u_char *sample_packet = s_packet + ip_length + 24;

  for (int i = 0; i < static_cast<int>(num_samples); i++) {


    debug_print(1, KGRN
            "\n\t###Flow Sample:%d\n", i + 1);
    auto sflow_sample_header = detail::to_host_order(*reinterpret_cast<uint32_t const *>(sample_packet));
    auto sflow_sample_type = sflow_sample_header & 0X00000FFF;
    auto sflow_sample_length = detail::to_host_order(*reinterpret_cast<uint32_t const *>(sample_packet + 4));

    debug_print(1, "\n"
            "\tsFlowSampleTypeV:\t%02x\n"
            "\tsFlowSampleLength:\t%02x\n", sflow_sample_type, sflow_sample_length
    );
    //Samples TYPE (Flow sample or Counter Sample) enterprise=0,format=1
    if (sflow_sample_type == 1) {
      //dissect FLOW Sample
      auto events_header = read_sflow_flowsample(sample_packet + 8);
      sflow_s_queue_.insert(sflow_s_queue_.end(), events_header.begin(), events_header.end());
    } else {
      debug_print(1, "Counter Samples are not implemented");
    }
    //Points to next Sflow PACKET (Header 8 bytes + samplelength)
    sample_packet = (sample_packet + 8 + sflow_sample_length);
    debug_print(1, KGRN
            "\n\t###Flow Sample:%d END###\n"
            KWHT, i + 1);
  }
  return sflow_s_queue_;
}

expected<void> reader::schema(vast::schema const &sch) {
  auto t = sch.find("vast::packet");
  if (!t)
    return make_error(ec::format_error, "did not find packet type in schema");
  if (!congruent(packet_type_, *t))
    return make_error(ec::format_error, "incongruent schema provided");
  packet_type_ = *t;
  return no_error;
}

expected<schema> reader::schema() const {
  vast::schema sch;
  sch.add(packet_type_);
  return sch;
}

const char *reader::name() const {
  return "sflow-reader";
}

writer::writer(std::string trace, size_t flush_interval)
        : flush_interval_{flush_interval},
          trace_{std::move(trace)} {
}

writer::~writer() {
  if (dumper_)
    ::pcap_dump_close(dumper_);
  if (pcap_)
    ::pcap_close(pcap_);
}

expected<void> writer::write(event const &e) {
  if (!pcap_) {
#ifdef PCAP_TSTAMP_PRECISION_NANO
    pcap_ = ::pcap_open_dead_with_tstamp_precision(DLT_RAW, 65535,
                                                   PCAP_TSTAMP_PRECISION_NANO);
#else
    pcap_ = ::pcap_open_dead(DLT_RAW, 65535);
#endif
    if (!pcap_)
      return make_error(ec::format_error, "failed to open pcap handle");
    dumper_ = ::pcap_dump_open(pcap_, trace_.c_str());
    if (!dumper_)
      return make_error(ec::format_error, "failed to open pcap dumper");
  }
  if (!congruent(e.type(), pcap_packet_type))
    return make_error(ec::format_error, "invalid pcap packet type");
  auto v = get_if<vector>(e.data());
  VAST_ASSERT(v);
  VAST_ASSERT(v->size() == 2);
  auto payload = get_if<std::string>((*v)[1]);
  VAST_ASSERT(payload);
  // Make PCAP header.
  ::pcap_pkthdr header;
  auto ns = e.timestamp().time_since_epoch().count();
  header.ts.tv_sec = ns / 1000000000;
#ifdef PCAP_TSTAMP_PRECISION_NANO
  header.ts.tv_usec = ns % 1000000000;
#else
  ns /= 1000;
header.ts.tv_usec = ns % 1000000;
#endif
  header.caplen = payload->size();
  header.len = payload->size();
  // Dump packet.
  ::pcap_dump(reinterpret_cast<uint8_t *>(dumper_), &header,
              reinterpret_cast<uint8_t const *>(payload->c_str()));
  if (++total_packets_ % flush_interval_ == 0) {
    auto r = flush();
    if (!r)
      return r.error();
  }
  return no_error;
}

expected<void> writer::flush() {
  if (!dumper_)
    return make_error(ec::format_error, "pcap dumper not open");
  VAST_DEBUG(name(), "flushes at packet", total_packets_);
  if (::pcap_dump_flush(dumper_) == -1)
    return make_error(ec::format_error, "failed to flush");
  return no_error;
}

const char *writer::name() const {
  return "pcap-writer";
}

} // namespace pcap
} // namespace format
} // namespace vast
