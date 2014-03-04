#ifndef VAST_IO_SERIALIZATION_H
#define VAST_IO_SERIALIZATION_H

#include "vast/config.h"
#include "vast/serialization.h"
#include "vast/io/container_stream.h"
#include "vast/io/compressed_stream.h"
#include "vast/io/file_stream.h"

namespace vast {
namespace io {

namespace detail {

template <typename Serializer, typename T>
void do_serialize(Serializer& s, T const& x)
{
  s << x;
}

template <typename Serializer, typename T0, typename... Ts>
void do_serialize(Serializer& s, T0 const& x, Ts const&... xs)
{
  do_serialize(s, x);
  do_serialize(s, xs...);
}

template <typename Deserializer, typename T>
void do_deserialize(Deserializer& s, T& x)
{
  s >> x;
}

template <typename Deserializer, typename T0, typename... Ts>
void do_deserialize(Deserializer& s, T0& x, Ts&... xs)
{
  do_deserialize(s, x);
  do_deserialize(s, xs...);
}

} // namespace detail

template <
  typename... Ts,
  typename Container,
  typename Serializer = binary_serializer
>
bool archive(Container& c, Ts const&... xs)
{
  auto sink = io::make_container_output_stream(c);
  Serializer s{sink};
  detail::do_serialize(s, xs...);

  return true;
}

template <
  typename... Ts,
  typename Container,
  typename Deserializer = binary_deserializer
>
bool unarchive(Container const& c, Ts&... xs)
{
  auto source = make_container_input_stream(c);
  Deserializer d{source};
  detail::do_deserialize(d, xs...);

  return true;
}

template <
  typename... Ts,
  typename Serializer = binary_serializer
>
bool archive(path const& filename, Ts const&... xs)
{
  if (! exists(filename.parent()) && ! mkdir(filename.parent()))
    return false;

  file f{filename};
  if (! f.open(file::write_only))
    return false;

  io::file_output_stream sink{f};
  Serializer s{sink};
  detail::do_serialize(s, xs...);

  return true;
}

template <
  typename... Ts,
  typename Deserializer = binary_deserializer
>
bool unarchive(path const& filename, Ts&... xs)
{
  file f{filename};
  if (! f.open(file::read_only))
    return false;

  io::file_input_stream source{f};
  Deserializer d{source};
  detail::do_deserialize(d, xs...);

  return true;
}

template <typename... Ts, typename Container>
bool compress(compression method, Container& c, Ts const&... xs)
{
  auto buf = make_container_output_stream(c);
  std::unique_ptr<compressed_output_stream> out{
      make_compressed_output_stream(method, buf)};

  binary_serializer s{*out};
  detail::do_serialize(s, xs...);

  return true;
}

template <typename... Ts, typename Container>
bool decompress(compression method, Container const& c, Ts&... xs)
{
  auto buf = make_array_input_stream(c);
  std::unique_ptr<compressed_input_stream> in{
      make_compressed_input_stream(method, buf)};

  binary_deserializer d{*in};
  detail::do_deserialize(d, xs...);

  return true;
}

template <typename... Ts>
bool compress(compression method, path const& filename, Ts const&... xs)
{
  if (! exists(filename.parent()) && ! mkdir(filename.parent()))
    return false;

  file f{filename};
  if (! f.open(file::write_only))
    return false;

  io::file_output_stream sink{f};
  std::unique_ptr<compressed_output_stream> out{
      make_compressed_output_stream(method, sink)};

  binary_serializer s{*out};
  detail::do_serialize(s, xs...);

  return true;
}

template <typename... Ts>
bool decompress(compression method, path const& filename, Ts&... xs)
{
  file f{filename};
  if (! f.open(file::read_only))
    return false;

  io::file_input_stream source{f};
  std::unique_ptr<compressed_input_stream> in{
      make_compressed_input_stream(method, source)};

  binary_deserializer d{*in};
  detail::do_deserialize(d, xs...);

  return true;
}

} // namespace io
} // namespace vast

#endif
