#include "../../esp32_marauder/EvidencePool.h"
#include <cassert>
#include <cstdint>
#include <deque>
#include <vector>
using namespace passive_evidence;
struct Header { uint32_t seq; uint16_t length; uint16_t marker; };
int main() {
  // Exact byte fit, rejected admission and too-small destination do not mutate FIFO.
  PacketPool<Header, 24, 4, 16> exact;
  Header h{1,14,0xbeef}, out{};
  uint8_t payload[16]; for (unsigned i=0;i<16;++i) payload[i]=i;
  uint8_t received[16]{};
  assert(exact.push(h,payload,14)==PoolPush::Accepted);
  assert(exact.used()==24 && exact.count()==1);
  assert(exact.push(h,payload,1)==PoolPush::ByteLimit);
  assert(!exact.pop(out,received,13));
  assert(exact.used()==24 && exact.count()==1);
  assert(exact.pop(out,received,sizeof(received)));
  assert(out.seq==1 && out.marker==0xbeef && out.length==14);
  for(unsigned i=0;i<14;++i) assert(received[i]==i);
  assert(exact.used()==0 && !exact.pop(out,received,sizeof(received)));
  assert(exact.push(h,payload,15)==PoolPush::ByteLimit);
  assert(exact.push(h,payload,17)==PoolPush::InvalidLength);
  assert(exact.push(h,nullptr,1)==PoolPush::InvalidLength);
  assert(exact.count()==0 && exact.peakBytes()==24 && exact.peakCount()==1);
  exact.reset(); assert(exact.peakBytes()==0 && exact.peakCount()==0);

  PacketPool<Header, 128, 2, 16> count;
  h.length=0;
  assert(count.push(h,nullptr,0)==PoolPush::Accepted);
  assert(count.push(h,nullptr,0)==PoolPush::Accepted);
  assert(count.push(h,nullptr,0)==PoolPush::RecordLimit);
  assert(count.pop(out,nullptr,0) && out.length==0);
  assert(count.push(h,nullptr,0)==PoolPush::Accepted);

  // An odd-sized ring forces both metadata and payload to straddle its boundary.
  // Compare many admitted/rejected operations against an independent FIFO model.
  PacketPool<Header, 173, 7, 64> pool;
  struct Expected { Header header; std::vector<uint8_t> bytes; };
  std::deque<Expected> fifo;
  size_t bytes=0;
  uint32_t rng=12345;
  for(uint32_t seq=1;seq<=10000;++seq) {
    rng=rng*1664525u+1013904223u;
    if (((rng >> 24) & 1) && !fifo.empty()) {
      const auto expected=fifo.front();
      uint8_t actual[64]{};
      assert(pool.pop(out,actual,sizeof(actual)));
      assert(out.seq==expected.header.seq && out.length==expected.bytes.size());
      assert(out.marker==0xbeef);
      for(size_t i=0;i<expected.bytes.size();++i) assert(actual[i]==expected.bytes[i]);
      bytes-=10+expected.bytes.size(); fifo.pop_front();
    } else {
      size_t len=(rng>>8)%65;
      Expected item{{seq,(uint16_t)len,0xbeef},std::vector<uint8_t>(len)};
      for(size_t i=0;i<len;++i) item.bytes[i]=(seq+i)%256;
      auto result=pool.push(item.header,item.bytes.data(),len);
      if(fifo.size()==7) assert(result==PoolPush::RecordLimit);
      else if(bytes+10+len>173) assert(result==PoolPush::ByteLimit);
      else { assert(result==PoolPush::Accepted); bytes+=10+len;fifo.push_back(item); }
    }
    assert(pool.count()==fifo.size() && pool.used()==bytes);
    assert(pool.peakCount()<=7 && pool.peakBytes()<=173);
  }
  pool.reset(); assert(pool.used()==0 && pool.count()==0);
  assert(!pool.pop(out,received,sizeof(received)));
  // Exercise the production byte/count/payload bounds, including a completely full ring.
  struct ProductionHeader { uint8_t bytes[32]; };
  PacketPool<ProductionHeader,32768,64,1024> production;
  ProductionHeader ph{}, phOut{};
  uint8_t large[1025]{}, largeOut[1024]{};
  for(unsigned i=0;i<1025;++i) large[i]=i%251;
  for(unsigned i=0;i<64;++i) {
    ph.bytes[0]=i;
    assert(production.push(ph,large,31)==PoolPush::Accepted);
  }
  assert(production.used()==4160 && production.peakCount()==64);
  assert(production.push(ph,large,1)==PoolPush::RecordLimit);
  for(unsigned i=0;i<64;++i) {
    assert(production.pop(phOut,largeOut,sizeof(largeOut)));
    assert(phOut.bytes[0]==i);
    for(unsigned j=0;j<31;++j) assert(largeOut[j]==large[j]);
  }
  assert(production.used()==0);
  assert(production.push(ph,large,1025)==PoolPush::InvalidLength);
  for(unsigned i=0;i<30;++i) {
    ph.bytes[0]=i;
    assert(production.push(ph,large,1024)==PoolPush::Accepted);
  }
  assert(production.used()==31740);
  assert(production.push(ph,large,1024)==PoolPush::ByteLimit);
  ph.bytes[0]=30;
  assert(production.push(ph,large,994)==PoolPush::Accepted);
  assert(production.used()==32768);
  assert(production.push(ph,nullptr,0)==PoolPush::ByteLimit);
  for(unsigned i=0;i<31;++i) {
    assert(production.pop(phOut,largeOut,sizeof(largeOut)));
    assert(phOut.bytes[0]==i);
    for(unsigned j=0;j<(i==30?994:1024);++j) assert(largeOut[j]==large[j]);
  }
  assert(production.used()==0 && production.count()==0);

}
