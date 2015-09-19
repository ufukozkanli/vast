#ifndef VAST_ACTOR_SOURCE_BYTE_BASED_H
#define VAST_ACTOR_SOURCE_BYTE_BASED_H

#include <algorithm>

#include "vast/actor/source/base.h"
#include "vast/io/getline.h"
#include "vast/io/stream.h"
#include "vast/util/assert.h"

namespace vast {
namespace source {

/// A byte-based source that transforms an input stream into lines.
template <typename Derived>
class byte_based : public base<Derived>
{
protected:
  /// Constructs a a byte-based source.
  /// @param name The name of the actor.
  /// @param is The input stream to read from.
  byte_based(char const* name, std::unique_ptr<io::input_stream> is)
    : base<Derived>{name},
      input_stream_{std::move(is)}
  {
    VAST_ASSERT(input_stream_ != nullptr);
  }

  /// Imports a file in its entirety.
  /// @returns The byte vector.
  std::vector<uint8_t> import()
  {
    uint8_t const* buf;
    size_t size;
    std::vector<uint8_t> bytes;
    while (input_stream_->next(reinterpret_cast<void const**>(&buf), &size))
      std::copy_n(buf, size, std::back_inserter(bytes));
    return bytes;
  }

private:
  std::unique_ptr<io::input_stream> input_stream_;
};

} // namespace source
} // namespace vast

#endif
