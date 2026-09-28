#pragma once
#include <stddef.h>
#include <stdint.h>
namespace passive_evidence {
// Promiscuous sig_len includes the trailing four FCS bytes on this pinned IDF.
inline size_t probeLength(const uint8_t* frame, size_t size) {
  if (!frame || size < 30 || (frame[0] & 0xfc) != 0x40) return 0;
  // This mode supports the ordinary 24-byte management header, not +HTC.
  if (frame[1] & 0x80) return 0;
  return size - 4;
}
}
