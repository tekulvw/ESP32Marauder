#include "../../esp32_marauder/EvidencePacket.h"
#include <cassert>
#include <initializer_list>
#include <cstdint>
using namespace passive_evidence;
int main() {
  uint8_t frame[100]{};
  for (auto type : {0x40,0x50,0x80}) {
    frame[0]=type;
    unsigned minimum=type==0x40 ? 30 : 42;
    for (unsigned length=0; length<minimum; ++length) assert(managementLength(frame,length)==0);
    assert(managementLength(frame,minimum)==minimum-4);
    assert(managementLength(frame,100)==96);
    for (auto flag : {0x80,0x40,0x04,0x01,0x02}) {
      frame[1]=flag; assert(managementLength(frame,100)==0);
    }
    frame[1]=0; frame[22]=1; assert(managementLength(frame,100)==0); frame[22]=0;
  }
  frame[0]=0x48; assert(managementLength(frame,100)==0);  // data frame
  frame[0]=0x81; assert(managementLength(frame,100)==0);  // unknown protocol version
  assert(managementLength(nullptr,100)==0);
  frame[0]=0x80;
  frame[36]=5; frame[37]=1; frame[38]=4;  // TIM
  uint32_t hash=beaconFingerprint(frame,39);
  frame[24]=42; frame[22]=0x10; frame[38]=9;
  assert(beaconFingerprint(frame,39)==hash);
  frame[34]=1; assert(beaconFingerprint(frame,39)!=hash);
  BeaconSampler sampler;
  assert(!sampler.suppress(frame+10,6,hash,10));  // eligibility doesn't mark an unsent packet
  assert(!sampler.suppress(frame+10,6,hash,20));
  sampler.remember(frame+10,6,hash,20);
  assert(sampler.suppress(frame+10,6,hash,21));
  assert(!sampler.suppress(frame+10,1,hash,21));
  assert(!sampler.suppress(frame+10,6,hash+1,21));
  sampler.remember(frame+10,6,hash+1,21);
  assert(sampler.suppress(frame+10,6,hash,22));  // alternating variants cannot bypass sampling
  assert(!sampler.suppress(frame+10,6,hash,5000020));
  sampler.reset(); assert(!sampler.suppress(frame+10,6,hash,22));
}
