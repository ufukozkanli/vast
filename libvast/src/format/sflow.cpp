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
        : input_{std::move(input)} {
}

reader::~reader() {
  if (pcap_)
    ::pcap_close(pcap_);
}

expected<event> reader::read() {
  //IF SFLOW SAMPLES EXISTS
  if (!event_queue_.empty()) {
    event evt = std::move(event_queue_.front());
    event_queue_.erase(event_queue_.begin());
    return evt;
  }
  char buf[PCAP_ERRBUF_SIZE]; // for errors.
  if (!pcap_) {
    // Determine interfaces.
    pcap_if_t *iface;
    if (::pcap_findalldevs(&iface, buf) == -1)
      return make_error(ec::format_error,
                        "failed to enumerate interfaces: ", buf);
    for (auto i = iface; i != nullptr; i = i->next)
      if (input_ == i->name) {
        pcap_ = ::pcap_open_live(i->name, 65535, 1, 1000, buf);
        if (!pcap_) {
          ::pcap_freealldevs(iface);
          return make_error(ec::format_error, "failed to open interface ",
                            input_, ": ", buf);
        }
        if (pseudo_realtime_ > 0) {
          pseudo_realtime_ = 0;
          VAST_WARNING(name(), "ignores pseudo-realtime in live mode");
        }
        VAST_INFO(name(), "listens on interface " << i->name);
        break;
      }
    ::pcap_freealldevs(iface);
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
      if (pseudo_realtime_ > 0)
        VAST_INFO(name(), "uses pseudo-realtime factor 1/" << pseudo_realtime_);
    }
    VAST_INFO(name(), "cuts off flows after", cutoff_,
              "bytes in each direction");
    VAST_INFO(name(), "keeps at most", max_flows_, "concurrent flows");
    VAST_INFO(name(), "evicts flows after", max_age_ << "s of inactivity");
    VAST_INFO(name(), "expires flow table every", expire_interval_ << "s");
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
  connection conn;
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
      auto orig_h = reinterpret_cast<uint32_t const *>(layer3 + 12);
      auto resp_h = reinterpret_cast<uint32_t const *>(layer3 + 16);
      conn.src = {orig_h, address::ipv4, address::network};
      conn.dst = {resp_h, address::ipv4, address::network};
      layer4_proto = *(layer3 + 9);
      layer4 = layer3 + header_size;
      payload_size -= header_size;
    }
      break;
    case 0x86dd: {
      if (header->len < 14 + 40)
        return make_error(ec::format_error, "IPv6 header too short");
      auto orig_h = reinterpret_cast<uint32_t const *>(layer3 + 8);
      auto resp_h = reinterpret_cast<uint32_t const *>(layer3 + 24);
      conn.src = {orig_h, address::ipv4, address::network};
      conn.dst = {resp_h, address::ipv4, address::network};
      layer4_proto = *(layer3 + 6);
      layer4 = layer3 + 40;
      payload_size -= 40;
    }
      break;
  }
  if (layer4_proto == IPPROTO_TCP) {
    VAST_ASSERT(layer4);
    auto orig_p = *reinterpret_cast<uint16_t const *>(layer4);
    auto resp_p = *reinterpret_cast<uint16_t const *>(layer4 + 2);
    orig_p = detail::to_host_order(orig_p);
    resp_p = detail::to_host_order(resp_p);
    conn.sport = {orig_p, port::tcp};
    conn.dport = {resp_p, port::tcp};
    auto data_offset = *reinterpret_cast<uint8_t const *>(layer4 + 12) >> 4;
    payload_size -= data_offset * 4;
  } else if (layer4_proto == IPPROTO_UDP) {
    VAST_ASSERT(layer4);
    auto orig_p = *reinterpret_cast<uint16_t const *>(layer4);
    auto resp_p = *reinterpret_cast<uint16_t const *>(layer4 + 2);
    orig_p = detail::to_host_order(orig_p);
    resp_p = detail::to_host_order(resp_p);
    conn.sport = {orig_p, port::udp};
    conn.dport = {resp_p, port::udp};
    payload_size -= 8;

    conn.sport = {orig_p, port::udp};
    conn.dport = {resp_p, port::udp};
    payload_size -= 8;
    //LAYER 5 SFLOW
    //TRY TO PARSE SFLOW
    uint8_t const *layer5 = nullptr;

    layer5 = layer4 + 8;
    readSFlowDatagram(layer5);


  } else if (layer4_proto == IPPROTO_ICMP) {
    VAST_ASSERT(layer4);
    auto message_type = *reinterpret_cast<uint8_t const *>(layer4);
    auto message_code = *reinterpret_cast<uint8_t const *>(layer4 + 1);
    conn.sport = {message_type, port::icmp};
    conn.dport = {message_code, port::icmp};
    payload_size -= 8; // TODO: account for variable-size data.
  }
  return no_error;
}


struct Event {
  uint16_t TcpPortS;
  uint16_t TcpPortD;
  uint32_t IpAddressS;
  uint32_t IpAddressD;
  uint32_t *IpAddressS_P;
  uint32_t *IpAddressD_P;
  uint32_t PacketNumber;
};
FILE *fp = fopen ( "pcapTestResult.txt", "w" ) ;
Event currentEvent = {};
uint32_t currentPacketNumber;

int reader::readSflowFS_RP_HS_IPV4_TCP(const u_char *fs_TCP_Packet) {
  fprintf(fp,KRED "\n\t\t\t\t\t\t###TCP Record");
  auto sFS_RP_HS_IPV4_TCP_SourcePort = __bswap_16(*reinterpret_cast<uint16_t const *>(fs_TCP_Packet));
  auto sFS_RP_HS_IPV4_TCP_DestinationPort = __bswap_16(*reinterpret_cast<uint16_t const *>(fs_TCP_Packet + 2));

  fprintf(fp,"\n"
                 "\t\t\t\t\t\tTCPs:\t\t%d\n"
                 "\t\t\t\t\t\tTCPd:\t\t%d\n", sFS_RP_HS_IPV4_TCP_SourcePort, sFS_RP_HS_IPV4_TCP_DestinationPort
  );
  currentEvent.TcpPortS = sFS_RP_HS_IPV4_TCP_SourcePort;
  currentEvent.TcpPortD = sFS_RP_HS_IPV4_TCP_DestinationPort;
  fprintf(fp,"\n"
                 "\t\t\t\t\t\tsFS_RP_HS_IPV4_TCP_SourcePort:\t\t%02x\n"
                 "\t\t\t\t\t\tsFS_RP_HS_IPV4_TCP_DestinationPort:\t%02x\n", sFS_RP_HS_IPV4_TCP_SourcePort,
         sFS_RP_HS_IPV4_TCP_DestinationPort
  );

  fprintf(fp,"\n\t\t\t\t\t\t###TCP Record END\n" KWHT);
  return 0;
}

int reader::readSflowFS_RP_HS_IPV4(const u_char *fs_IPV4_Packet) {
  fprintf(fp,KBLU "\n\t\t\t\t\t###IPV4 Record");
  auto sFS_RP_HS_IPV4_Protocol = *reinterpret_cast<unsigned char const *>(fs_IPV4_Packet + 9);
  auto sFS_RP_HS_IPV4_Source = *reinterpret_cast<uint32_t const *>(fs_IPV4_Packet + 12);
  auto sFS_RP_HS_IPV4_Destination = *reinterpret_cast<uint32_t const *>(fs_IPV4_Packet + 16);


  //PRINT IPs
  struct in_addr ipS, ipD;
  ipS.s_addr = sFS_RP_HS_IPV4_Source;
  ipD.s_addr = sFS_RP_HS_IPV4_Destination;
  fprintf(fp,"\n"
                 "\t\t\t\t\tips:\t%s\n"
                 "\t\t\t\t\tipD:\t%s\n", inet_ntoa(ipS), inet_ntoa(ipD)
  );
  currentEvent.IpAddressS = sFS_RP_HS_IPV4_Source;
  currentEvent.IpAddressD = sFS_RP_HS_IPV4_Destination;
  //
  fprintf(fp,"\n"
                 "\t\t\t\t\tsFS_RP_HS_IPV4_Source:\t\t%02x\n"
                 "\t\t\t\t\tsFS_RP_HS_IPV4_Protocol:\t%02x\n", sFS_RP_HS_IPV4_Source, sFS_RP_HS_IPV4_Protocol
  );
  //Check if TCP
  if (sFS_RP_HS_IPV4_Protocol == 0x06) {
    readSflowFS_RP_HS_IPV4_TCP(fs_IPV4_Packet + 20);
  } else {
    fprintf(fp,"Not implemented FS->RP->HS->IPV4 Protocol");
  }
  fprintf(fp,KBLU "\n\t\t\t\t\t###IPV4 Record END\n\n" KWHT);
  return 0;
}

int reader::readSflowFlowSampleHeaderOfSampledPacketEthernet(const u_char *fs_HS_Packet) {
  fprintf(fp,KMAG "\n\t\t\t\t###Ethernet Record");
  auto sFS_RP_HS_Type = __bswap_16(*reinterpret_cast<uint16_t const *>(fs_HS_Packet + 12));
  fprintf(fp,"\n"
                 "\t\t\t\tsFS_RP_HS_Type:\t%02x\n", sFS_RP_HS_Type
  );
  //Check if IPV4
  if (sFS_RP_HS_Type == 0X0800) {
    readSflowFS_RP_HS_IPV4(fs_HS_Packet + 14);
  } else {
    fprintf(fp,"Not implemented..FS->RP->HS->Type\n");
  }
  fprintf(fp,KMAG "\t\t\t\t###Ethernet Record END\n\n" KWHT);
  return 0;
}

int reader::readSflowFlowSample(const u_char *fsPacket) {
  auto sFS_FlowRecord = __bswap_32(*reinterpret_cast<uint32_t const *>(fsPacket + 28));
  fprintf(fp,"\n"
                 "\t\tsFS_FlowRecord:\t%02x\n", sFS_FlowRecord
  );
  const u_char *fsRawPacket = fsPacket + 32;
  for (int i = 0; i < static_cast<int>(sFS_FlowRecord); i++) {
    //
    fprintf(fp,KCYN "\n\t\t\t###Flow Record:%d", i + 1);

    auto sFS_FR_PacketHeaderV = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket));
    auto sFS_FR_FormatV = sFS_FR_PacketHeaderV & 0X00000FFF;
    auto sFS_FR_FlowDataLength = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket + 4));
    if (sFS_FR_FormatV == 1) {
      //###RAW PACKET HEADER:RP

      auto sFS_FR_RP_HeaderProtocol = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket + 8));
      auto sFS_FR_RP_OriginalPacketLength = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket + 20));
      fprintf(fp,"\n"
                     "\t\t\tsFS_RP_FormatV:\t\t\t%02x\n"
                     "\t\t\tsFS_RP_FlowDataLength:\t\t%02x\n"
                     "\t\t\tsFS_RP_OriginalPacketLength:\t%02x\n"
                     "\t\t\tsFS_RP_HeaderProtocol:\t\t%02x\n", sFS_FR_FormatV, sFS_FR_FlowDataLength,
             sFS_FR_RP_OriginalPacketLength, sFS_FR_RP_HeaderProtocol
      );
      if (sFS_FR_RP_HeaderProtocol == 1) {
        currentEvent = {};
        //packet_stream_ << "\nSFLOW|";
        currentEvent.PacketNumber = currentPacketNumber;
        readSflowFlowSampleHeaderOfSampledPacketEthernet(fsRawPacket + 24);

        connection conn;
        conn.src = {&currentEvent.IpAddressS, address::ipv4, address::network};
        conn.dst = {&currentEvent.IpAddressD, address::ipv4, address::network};
        conn.sport = {currentEvent.TcpPortS, port::tcp};
        conn.sport = {currentEvent.TcpPortD, port::tcp};
        //printf("a::%02x\n",currentEvent.IpAddressS);

        vector sFpacket;
        vector meta;
        meta.emplace_back(std::move(conn.src));
        meta.emplace_back(std::move(conn.dst));
        meta.emplace_back(std::move(conn.sport));
        meta.emplace_back(std::move(conn.dport));
        sFpacket.emplace_back(std::move(meta));

        event e{{std::move(sFpacket), packet_type_}};
        e.timestamp(timestamp::clock::now());


        //???e.timestamp(def.ts);
        event_queue_.push_back(std::move(e));

        //packet_string_ = packet_stream_.str();
        VAST_DEBUG(this, packet_string_ << "\n");
        //packet_stream_.str(std::string());

      } else {
        fprintf(fp,"Not implemented..FS->FR->HeaderProtocol\n");
      }
    } else {
      fprintf(fp,"Not implemented..FS->RP->Format\n");
    }

    fsRawPacket = fsRawPacket + sFS_FR_FlowDataLength + 8;
    fprintf(fp,KCYN "\t\t\t###Flow Record:%d END###\n" KWHT, i + 1);

  }
  return 0;
}

int reader::readSFlowDatagram(const u_char *sPacketP) {
  auto sDatagramVersionV = __bswap_32(*reinterpret_cast<uint32_t const *>(sPacketP));
  //CHECK IF UDP PACKET IS PARSABLE TO SFLOW
  if (!(sDatagramVersionV == 2 || sDatagramVersionV == 4 || sDatagramVersionV == 5))
    return -1;
  auto sAddressTypeV = *reinterpret_cast<uint32_t const *>(sPacketP + 4);

  const u_char *sSubAgentIdP;
  //IPV4 ? V6
  if (__bswap_32(sAddressTypeV) == 1) {
    //auto sAddressTypeV=*reinterpret_cast<uint32_t const*>(sPacketP+8);
    sSubAgentIdP = sPacketP + 12;
  } else if (sAddressTypeV == 1) {
    //auto sAddresTypeV=*reinterpret_cast<uint64_t const*>(sPacketP+8);
    sSubAgentIdP = sPacketP + 24;
  } else {
    fprintf(fp,"Sflow Ip Header Problem..\n");
    return 1;
  }
  auto sSubAgentIdV = *reinterpret_cast<uint32_t const *>(sSubAgentIdP);
  //----OTHER HEADER FIELDS

  //----HERE

  //
  //sSubAgentIdP is the new Packet Pointer
  auto sNumSamplesP = sSubAgentIdP + 12;
  auto sNumSamplesV = __bswap_32(*reinterpret_cast<uint32_t const *>(sNumSamplesP));

  fprintf(fp,"\n--\n"
                 "sDatagramVersionV:\t%02x\n"
                 "sAddressTypeV:\t\t%02x\n"
                 "sSubAgentIdV:\t\t%02X\n"
                 "sNumSamplesV:\t\t%02X\n"
                 "\n", sDatagramVersionV, sAddressTypeV, sSubAgentIdV, sNumSamplesV
  );

  //READ SFLOW SAMPLES
  auto sFlowP = sSubAgentIdP + 16;
  for (int i = 0; i < static_cast<int>(sNumSamplesV); i++) {
    fprintf(fp,KGRN "\n\t###Flow Sample:%d\n", i + 1);
    auto sFlowSampleHeaderV = __bswap_32(*reinterpret_cast<uint32_t const *>(sFlowP));
    auto sFlowSampleTypeV = sFlowSampleHeaderV & 0X00000FFF;
    auto sFlowSampleLength = __bswap_32(*reinterpret_cast<uint32_t const *>(sFlowP + 4));

    fprintf(fp,"\n"
                   "\tsFlowSampleTypeV:\t%02x\n"
                   "\tsFlowSampleLength:\t%02x\n", sFlowSampleTypeV, sFlowSampleLength
    );

    //enterprise=0,format=1
    if (sFlowSampleTypeV == 1) {
      //READ FLOW Sample
      reader::readSflowFlowSample(sFlowP + 8);
    } else {
      fprintf(fp,"Counter Samples are not implemented");
    }
    //NEXT Sflow PACKET
    sFlowP = (sFlowP + 8 + sFlowSampleLength);
    fprintf(fp,KGRN "\n\t###Flow Sample:%d END###\n" KWHT, i + 1);
  }
  return 0;
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
  return "pcap-reader";
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
