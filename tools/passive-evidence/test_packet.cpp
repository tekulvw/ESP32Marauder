#include "../../esp32_marauder/EvidencePacket.h"
#include <cassert>
#include <cstdint>
int main() {
  uint8_t frame[100]{};
  for (unsigned length=0; length<30; ++length)
    assert(passive_evidence::probeLength(frame,length)==0);
  frame[0]=0x40;
  assert(passive_evidence::probeLength(frame,30)==26);
  assert(passive_evidence::probeLength(frame,100)==96);
  frame[1]=0x80;
  assert(passive_evidence::probeLength(frame,100)==0);
  frame[1]=0; frame[0]=0x80;
  assert(passive_evidence::probeLength(frame,100)==0);
  assert(passive_evidence::probeLength(nullptr,100)==0);
}
