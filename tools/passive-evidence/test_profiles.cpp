#include "../../esp32_marauder/EvidenceProfile.h"
#include <assert.h>
#include <string>
using namespace passive_evidence;
int main() {
  ScanProfile p;
  assert(parseProfile("", p));
  assert(p.count==11 && p.wifiDwellMs==250 && p.bleWindowMs==500);
  const uint8_t expected[]={11,6,1,10,9,8,7,5,4,3,2};
  ScanWindow w=firstWindow(p);
  for (unsigned cycle=0; cycle<5; ++cycle) {
    for (unsigned i=0; i<11; ++i) {
      assert(!w.ble && w.index==i && p.channels[w.index]==expected[i]);
      assert(windowDurationUs(p,w)==250000);
      w=nextWindow(p,w);
    }
    assert(w.ble && windowDurationUs(p,w)==500000); w=nextWindow(p,w);
  }
  assert(parseProfile("focused 50 -",p));
  assert(p.count==3 && p.channels[0]==11 && p.channels[1]==6 && p.channels[2]==1);
  assert(parseProfile("focused 1000 2,8,4",p));
  w=firstWindow(p);
  for (unsigned i=0; i<100; ++i) {
    assert(!w.ble && w.index==i%3 && windowDurationUs(p,w)==1000000);
    w=nextWindow(p,w);
  }
  assert(parseProfile("survey 50 11,6,1,10,9,8,7,5,4,3,2",p));
  assert(p.wifiDwellMs==50 && p.bleWindowMs==500 && p.count==11);
  assert(parseProfile("wifi-only 250 11,6,1,10,9,8,7,5,4,3,2",p));
  assert(p.count==11 && p.bleWindowMs==0);
  assert(parseProfile("wifi-only 250 -",p));
  w=firstWindow(p);
  for (unsigned i=0;i<100;++i) { assert(!w.ble && w.index==i%11); w=nextWindow(p,w); }
  for (unsigned channel=1; channel<=11; ++channel) {
    assert(parseProfile(("fixed 250 "+std::to_string(channel)).c_str(),p));
    assert(p.count==1 && p.channels[0]==channel && p.bleWindowMs==0);
    w=firstWindow(p);
    for (unsigned i=0;i<100;++i) { assert(!w.ble && w.index==0); w=nextWindow(p,w); }
  }
  assert(parseProfile("ble-only 250 -",p));
  assert(p.count==0 && p.bleWindowMs==500);
  w=firstWindow(p);
  for (unsigned i=0;i<100;++i) { assert(w.ble && windowDurationUs(p,w)==500000); w=nextWindow(p,w); }
  const char* bad[]={"unknown 250 -", "survey", "survey 49 -", "survey 1001 -", "survey -1 -",
    "survey 9999999999999999999 -", "survey 250 1", "wifi-only 250 11,6,1", "fixed 250 -",
    "fixed 250 1,2", "fixed 250 0", "fixed 250 12", "fixed 250 1,", "focused 250 1,1",
    "focused 250 ,1", "focused 250 1,,2", "focused 250 1 2", "focused 250 1,2 ",
    "focused 250 1,2,3,4,5,6,7,8,9,10,11,1", "ble-only 250 1", "ble-only 250 - extra",
    "focused 250 ", "focused 250", "focused  250 -", "focused 250.0 -", "fixed 250 +1"};
  for (const char* input:bad) {
    ScanProfile original=p;
    assert(!parseProfile(input,p));
    assert(p.kind==original.kind && p.count==original.count && p.wifiDwellMs==original.wifiDwellMs);
  }
  // Exhaust all dwell limits through the same parser used by device commands.
  for (unsigned dwell=0; dwell<1050; ++dwell) {
    bool valid=parseProfile(("focused "+std::to_string(dwell)+" 11,1").c_str(),p);
    assert(valid==(dwell>=50 && dwell<=1000));
  }
}
