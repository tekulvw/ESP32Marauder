#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace passive_evidence {
enum class PoolPush { Accepted, RecordLimit, ByteLimit, InvalidLength };

// Bounded FIFO: a length prefix, trivially-copyable metadata and actual payload.
// The caller must exclude concurrent push/pop/reset/read operations. No allocation.
template<class Header, size_t Bytes, size_t MaxRecords, size_t MaxPayload>
class PacketPool {
 public:
  static constexpr size_t HEADER_BYTES = sizeof(uint16_t) + sizeof(Header);
  static_assert(std::is_trivially_copyable<Header>::value, "Metadata must be copyable as bytes");
  static_assert(Bytes >= HEADER_BYTES && MaxRecords > 0 && MaxPayload <= UINT16_MAX,
                "Invalid pool bounds");

  PoolPush push(const Header& header, const uint8_t* payload, size_t length) {
    if (length > MaxPayload || (length && !payload)) return PoolPush::InvalidLength;
    if (count_ == MaxRecords) return PoolPush::RecordLimit;
    const size_t required = HEADER_BYTES + length;
    if (required > Bytes - used_) return PoolPush::ByteLimit;
    size_t cursor = tail_;
    const uint16_t storedLength = static_cast<uint16_t>(length);
    write(cursor, &storedLength, sizeof(storedLength));
    write(cursor, &header, sizeof(header));
    write(cursor, payload, length);
    tail_ = cursor; used_ += required; ++count_;
    if (used_ > peakBytes_) peakBytes_ = used_;
    if (count_ > peakCount_) peakCount_ = count_;
    return PoolPush::Accepted;
  }

  bool pop(Header& header, uint8_t* payload, size_t capacity) {
    if (!count_) return false;
    size_t cursor = head_;
    uint16_t length;
    read(cursor, &length, sizeof(length));
    if (length > capacity || (length && !payload)) return false;
    read(cursor, &header, sizeof(header));
    read(cursor, payload, length);
    head_ = cursor; used_ -= HEADER_BYTES + length; --count_;
    return true;
  }

  void reset() { head_=tail_=used_=count_=peakBytes_=peakCount_=0; }
  size_t count() const { return count_; }
  size_t used() const { return used_; }
  size_t peakCount() const { return peakCount_; }
  size_t peakBytes() const { return peakBytes_; }

 private:
  void write(size_t& cursor, const void* source, size_t length) {
    if (!length) return;
    const size_t first = length < Bytes-cursor ? length : Bytes-cursor;
    std::memcpy(storage_+cursor, source, first);
    if (length > first) std::memcpy(storage_, static_cast<const uint8_t*>(source)+first, length-first);
    cursor = (cursor+length)%Bytes;
  }
  void read(size_t& cursor, void* destination, size_t length) const {
    if (!length) return;
    const size_t first = length < Bytes-cursor ? length : Bytes-cursor;
    std::memcpy(destination, storage_+cursor, first);
    if (length > first) std::memcpy(static_cast<uint8_t*>(destination)+first, storage_, length-first);
    cursor = (cursor+length)%Bytes;
  }
  uint8_t storage_[Bytes]{};
  size_t head_=0, tail_=0, used_=0, count_=0, peakBytes_=0, peakCount_=0;
};
}  // namespace passive_evidence
