#include "../../esp32_marauder/EvidencePacket.h"
#include <cassert>
#include <initializer_list>
using namespace passive_evidence;
int main() {
  uint8_t f[100]{};
  f[0]=0x08; assert(evidenceHeaderLength(f,28)==24); assert(evidenceHeaderLength(f,27)==0);
  f[1]=3; assert(evidenceHeaderLength(f,34)==30); assert(evidenceHeaderLength(f,33)==0);
  f[0]=0x88; assert(evidenceHeaderLength(f,36)==32); assert(evidenceHeaderLength(f,35)==0);
  f[1]=0xc3; assert(evidenceHeaderLength(f,40)==36); assert(evidenceHeaderLength(f,39)==0);
  f[31]=1; assert(evidenceHeaderLength(f,100)==0); f[31]=0;
  f[0]=0xc0; f[1]=0; assert(evidenceHeaderLength(f,28)==24);
  f[1]=1; assert(evidenceHeaderLength(f,100)==0); f[1]=0;
  for (auto fc : {0x40,0x50,0x80,0xd4,0xd8,0x09}) { f[0]=fc; assert(evidenceHeaderLength(f,100)==0); }
  assert(evidenceHeaderLength(nullptr,100)==0);
  HeaderSampler s; s.reset(); f[0]=8;
  auto key=headerFingerprint(f,24,6);
  assert(!s.suppress(key,10)); s.remember(key,10); assert(s.suppress(key,11));
  f[22]=42; f[1]=8; assert(headerFingerprint(f,24,6)==key); // sequence/retry not identity
  f[4]=1; assert(headerFingerprint(f,24,6)!=key);
  assert(!s.suppress(key,1000010));
  assert(!s.limited(20));
  for (unsigned i=1;i<HeaderSampler::RATE_LIMIT;++i) s.remember(key+i,20);
  assert(s.limited(21)); assert(!s.limited(1000010));
}
