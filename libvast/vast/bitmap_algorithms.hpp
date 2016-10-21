#ifndef VAST_BITMAP_ALGORITHMS_HPP
#define VAST_BITMAP_ALGORITHMS_HPP

#include <algorithm>
#include <iterator>
#include <queue>
#include <type_traits>

#include "vast/bits.hpp"
#include "vast/optional.hpp"
#include "vast/detail/assert.hpp"
#include "vast/detail/type_traits.hpp"

namespace vast {

class bitmap;

namespace detail {

template <class T, class U>
struct eval_result_type {
  using type = std::conditional_t<std::is_same<T, U>::value, T, bitmap>;
};

template <class T, class U>
using eval_result_type_t = typename eval_result_type<T, U>::type;

} // namespace detail

/// Applies a bitwise operation on two immutable bitmaps, writing the result
/// into a new bitmap.
/// @tparam FillLHS A boolean flag that controls the algorithm behavior after
///                 one sequence has reached its end. If `true`, the algorithm
///                 will append the remaining bits of *lhs* to the result iff
///                 *lhs* is the longer bitmap. If `false`, the algorithm
///                 returns the result after the first sequence has reached an
///                 end.
/// @tparam FillRHS The same as *fill_lhs*, except that it concerns *rhs*.
/// @param lhs The LHS of the operation.
/// @param rhs The RHS of the operation
/// @param op The bitwise operation as block-wise lambda, e.g., for XOR:
///
///     [](auto lhs, auto rhs) { return lhs ^ rhs; }
///
/// @returns The result of a bitwise operation between *lhs* and *rhs*
/// according to *op*.
template <bool FillLHS, bool FillRHS, class LHS, class RHS, class Operation>
detail::eval_result_type_t<LHS, RHS>
binary_eval(LHS const& lhs, RHS const& rhs, Operation op) {
  using result_type = detail::eval_result_type_t<LHS, RHS>;
  static_assert(
    detail::are_same<
      typename LHS::word_type,
      typename RHS::word_type,
      typename result_type::word_type
    >::value,
    "LHS, RHS, and result type must exhibit same word type");
  using word = typename result_type::word_type;
  result_type result;
  // Check corner cases.
  if (lhs.empty() && rhs.empty())
    return result;
  if (lhs.empty())
    return rhs;
  if (rhs.empty())
    return lhs;
  // Initialize LHS.
  auto lhs_range = bit_range(lhs);
  auto lhs_begin = lhs_range.begin();
  auto lhs_end = lhs_range.end();
  auto lhs_bits = lhs_begin->size();
  // Initialize RHS.
  auto rhs_range = bit_range(rhs);
  auto rhs_begin = rhs_range.begin();
  auto rhs_end = rhs_range.end();
  auto rhs_bits = rhs_begin->size();
  // TODO: figure out whether we still need the notion of a "fill," i.e., a
  // homogeneous sequence greater-than-or-equal to the word size, or whether
  // we can operate on the bit sequences directly, possibly leading to
  // simplifications.
  auto is_fill = [](auto x) {
    return x->homogeneous() && x->size() >= word::width;
  };
  // Iterate.
  while (lhs_begin != lhs_end && rhs_begin != rhs_end) {
    if (is_fill(lhs_begin) && is_fill(rhs_begin)) {
      auto min_bits = std::min(lhs_bits, rhs_bits);
      auto block = op(lhs_begin->data(), rhs_begin->data());
      VAST_ASSERT(word::all_or_none(block));
      result.append_bits(block, min_bits);
      lhs_bits -= min_bits;
      rhs_bits -= min_bits;
    } else if (is_fill(lhs_begin)) {
      VAST_ASSERT(rhs_bits > 0);
      VAST_ASSERT(rhs_bits <= word::width);
      auto block = op(lhs_begin->data(),
                      rhs_begin->data() & word::lsb_fill(rhs_bits));
      result.append_block(block);
      lhs_bits -= word::width;
      rhs_bits = 0;
    } else if (is_fill(rhs_begin)) {
      VAST_ASSERT(lhs_bits > 0);
      VAST_ASSERT(lhs_bits <= word::width);
      auto block = op(lhs_begin->data() & word::lsb_fill(lhs_bits),
                      rhs_begin->data());
      result.append_block(block);
      rhs_bits -= word::width;
      lhs_bits = 0;
    } else {
      auto block = op(lhs_begin->data() & word::lsb_fill(lhs_bits),
                      rhs_begin->data() & word::lsb_fill(rhs_bits));
      result.append_block(block, std::max(lhs_bits, rhs_bits));
      lhs_bits = rhs_bits = 0;
    }
    if (lhs_bits == 0 && ++lhs_begin != lhs_end)
      lhs_bits = lhs_begin->size();
    if (rhs_bits == 0 && ++rhs_begin != rhs_end)
      rhs_bits = rhs_begin->size();
  }
  if (FillLHS) {
    while (lhs_begin != lhs_end) {
      if (is_fill(lhs_begin))
        result.append_bits(lhs_begin->data(), lhs_bits);
      else
        result.append_block(lhs_begin->data(), lhs_begin->size());
      ++lhs_begin;
      if (lhs_begin != lhs_end)
        lhs_bits = lhs_begin->size();
    }
  }
  if (FillRHS) {
    while (rhs_begin != rhs_end) {
      if (is_fill(rhs_begin))
        result.append_bits(rhs_begin->data(), rhs_bits);
      else
        result.append_block(rhs_begin->data(), rhs_begin->size());
      ++rhs_begin;
      if (rhs_begin != rhs_end)
        rhs_bits = rhs_begin->size();
    }
  }
  // If the result has not yet been filled with the remaining bits of either
  // LHS or RHS, we have to fill it up with zeros. This is necessary, for
  // example, to ensure that the complement of the result can still be used in
  // further bitwise operations with bitmaps having the size of
  // max(size(LHS), size(RHS)).
  auto max_size = std::max(lhs.size(), rhs.size());
  VAST_ASSERT(max_size >= result.size());
  result.append_bits(false, max_size - result.size());
  return result;
}

/// Evaluates a binary operation over multiple bitmaps.
/// @param begin The beginning of the bitmap range.
/// @param end The end of the bitmap range.
/// @param op A binary bitwise operation to execute over the given bitmaps.
/// @returns The application of *op* over the bitmaps *[begin,end)*.
/// @note This algorithm is "Option 3" described in setion 5 in Wu et al.'s
///       2004 paper titled *On the Performance of Bitmap Indices for
///       High-Cardinality Attributes*.
template <class Iterator, class Operation>
auto nary_eval(Iterator begin, Iterator end, Operation op) {
  using bitmap_type = std::decay_t<decltype(*begin)>;
  // Exposes a pointer to represent either a non-owned bitmap from the input
  // sequence or an intermediary result.
  struct element {
    explicit element(bitmap_type const* bm) : bitmap{bm} {
    }
    explicit element(bitmap_type&& bm)
      : data{std::make_shared<bitmap_type>(std::move(bm))},
        bitmap{data.get()} {
    }
    std::shared_ptr<bitmap_type> data;
    bitmap_type const* bitmap;
  };
  auto cmp = [](auto& lhs, auto& rhs) {
    return lhs.bitmap->size() > rhs.bitmap->size();
  };
  std::priority_queue<element, std::vector<element>, decltype(cmp)> queue{cmp};
  for (; begin != end; ++begin)
    queue.emplace(&*begin);
  // Evaluate bitmaps.
  while (!queue.empty()) {
    auto lhs = queue.top();
    queue.pop();
    if (queue.empty())
      // When our input sequence consists of a single bitmap, we end up with an
      // element that has no data. Otherwise we would have had a least one
      // intermediary result, which would be stored as data.
      return lhs.data ? std::move(*lhs.data) : *lhs.bitmap;
    auto rhs = queue.top();
    queue.pop();
    queue.emplace(op(*lhs.bitmap, *rhs.bitmap));
  }
  return bitmap_type{};
}

template <class LHS, class RHS>
auto binary_and(LHS const& lhs, RHS const& rhs) {
  auto op = [](auto x, auto y) { return x & y; };
  return binary_eval<false, false>(lhs, rhs, op);
}

template <class LHS, class RHS>
auto binary_or(LHS const& lhs, RHS const& rhs) {
  auto op = [](auto x, auto y) { return x | y; };
  return binary_eval<true, true>(lhs, rhs, op);
}

template <class LHS, class RHS>
auto binary_xor(LHS const& lhs, RHS const& rhs) {
  auto op = [](auto x, auto y) { return x ^ y; };
  return binary_eval<true, true>(lhs, rhs, op);
}

template <class LHS, class RHS>
auto binary_nand(LHS const& lhs, RHS const& rhs) {
  auto op = [](auto x, auto y) { return x & ~y; };
  return binary_eval<true, false>(lhs, rhs, op);
}

template <class LHS, class RHS>
auto binary_nor(LHS const& lhs, RHS const& rhs) {
  auto op = [](auto x, auto y) { return x | ~y; };
  return binary_eval<true, true>(lhs, rhs, op);
}

template <class Iterator>
auto nary_and(Iterator begin, Iterator end) {
  auto op = [](auto x, auto y) { return x & y; };
  return nary_eval(begin, end, op);
}

template <class Iterator>
auto nary_or(Iterator begin, Iterator end) {
  auto op = [](auto x, auto y) { return x | y; };
  return nary_eval(begin, end, op);
}

template <class Iterator>
auto nary_xor(Iterator begin, Iterator end) {
  auto op = [](auto x, auto y) { return x ^ y; };
  return nary_eval(begin, end, op);
}

/// Computes the *rank* of a Bitmap, i.e., the number of occurrences of a bit
/// value in *B[0,i]*.
/// @tparam Bit The bit value to count.
/// @param bm The bitmap whose rank to compute.
/// @param i The offset where to end counting.
/// @returns The population count of *bm* up to and including position *i*.
/// @pre `i < bm.size()`
template <bool Bit = true, class Bitmap>
typename Bitmap::size_type
rank(Bitmap const& bm, typename Bitmap::size_type i = 0) {
  VAST_ASSERT(i < bm.size());
  if (bm.empty())
    return 0;
  if (i == 0)
    i = bm.size() - 1;
  auto result = typename Bitmap::size_type{0};
  auto n = typename Bitmap::size_type{0};
  for (auto b : bit_range(bm)) {
    auto count = b.count();
    result += Bit ? count : b.size() - count;
    if (i >= n && i < n + b.size()) {
      // Adjust for last sequence.
      auto size = i - n + 1;
      auto last = bits<typename Bitmap::block_type>{b.data(), size}.count();
      result -= Bit ? count - last : b.size() - count - (size - last);
      break;
    }
    n += b.size();
  }
  return result;
}

/// Computes the position of the i-th occurrence of a bit.
/// @tparam Bit the bit value to locate.
/// @param bm The bitmap to select from.
/// @param i The position of the *i*-th occurrence of *Bit* in *bm*.
/// @pre `i > 0`
template <bool Bit = true, class Bitmap>
typename Bitmap::size_type
select(Bitmap const& bm, typename Bitmap::size_type i) {
  VAST_ASSERT(i > 0);
  auto cum = typename Bitmap::size_type{0};
  auto n = typename Bitmap::size_type{0};
  for (auto b : bit_range(bm)) {
    auto count = Bit ? b.count() : b.size() - b.count();
    if (cum + count >= i) {
      // Last sequence.
      if (b.size() > Bitmap::word_type::width)
        return n + (i - cum - 1);
      for (auto j = 0u; j < b.size(); ++j)
        if (Bitmap::word_type::test(b.data(), j) == Bit)
          if (++cum == i)
            return n + j;
    }
    cum += count;
    n += b.size();
  }
  return Bitmap::word_type::npos;
}

} // namespace vast

#endif
