#include "configs.h"
#ifdef MARAUDER_C5
#include "PassiveEvidence.h"
#include "EvidencePacket.h"
#include "WiFiScan.h"
#include "EvidencePool.h"
#include <esp_random.h>

extern WiFiScan wifi_scan_obj;

namespace passive_evidence {
namespace {
constexpr size_t MAX_BYTES = 1024;
constexpr unsigned DRAIN_PACKET_LIMIT = 16;
constexpr uint64_t DRAIN_BUDGET_US = 4000;
#if ARDUINO_USB_CDC_ON_BOOT
constexpr unsigned QUEUE_CAPACITY = 64;
constexpr const char* TRANSPORT = "usb_serial_jtag";
#else
// Bound the stop tail within the host deadline on the slower UART stream.
constexpr unsigned QUEUE_CAPACITY = 32;
constexpr const char* TRANSPORT = "uart0";
#endif
constexpr uint8_t CHANNELS[] = {11, 6, 1, 10, 9, 8, 7, 5, 4, 3, 2};
constexpr size_t POOL_BYTES = 32 * 1024;
struct RecordHeader {
  uint64_t us;
  uint32_t seq, beaconHash;
  uint16_t len, original;
  int8_t rssi;
  uint8_t radio, channel, addressType, advType;
  uint8_t mac[6];
  uint8_t headerOnly;
};
struct Record : RecordHeader { uint8_t bytes[MAX_BYTES]; };
using EvidencePool = PacketPool<RecordHeader, POOL_BYTES, QUEUE_CAPACITY, MAX_BYTES>;
EvidencePool pool;
portMUX_TYPE guard = portMUX_INITIALIZER_UNLOCKED;
bool running = false;
bool accepting = false;
bool wifiReady = false;
bool bleReady = false;
bool bleWindow = false;
bool windowOpen = false;
uint32_t seen = 0, dropped = 0, beaconSuppressed = 0;
uint32_t droppedRecords = 0, droppedBytes = 0, droppedInvalid = 0;
BeaconSampler beaconSampler;
HeaderSampler headerSampler;
uint32_t headersSeen=0, headersSuppressed=0, headersLimited=0, headersQueued=0;
uint32_t stream = 0;
uint64_t windowStart = 0, statusAt = 0;
uint8_t channelIndex = 0;
NimBLEScan* scan = nullptr;

uint64_t now() { return static_cast<uint64_t>(esp_timer_get_time()); }
void header(const char* event) {
  Serial.printf("@WARD:{\"v\":1,\"event\":\"%s\",\"stream\":\"%08lx\"", event, (unsigned long)stream);
}
void error(const char* reason) {
  header("error"); Serial.printf(",\"message\":\"%s\"}\n", reason);
}
void enqueue(Record& record) {
  portENTER_CRITICAL(&guard);
  if (accepting) {
    bool beacon = record.radio == 0 && record.bytes[0] == 0x80;
    if (record.headerOnly) {
      ++headersSeen;
      if (headerSampler.suppress(record.beaconHash,record.us)) {
        ++headersSuppressed; portEXIT_CRITICAL(&guard); return;
      }
      // Preserve at least half the record slots for probes/AP IEs/BLE.
      if (headerSampler.limited(record.us) || pool.count()>=QUEUE_CAPACITY/2) {
        ++headersLimited; portEXIT_CRITICAL(&guard); return;
      }
    }
    if (beacon && beaconSampler.suppress(record.bytes+10, record.channel, record.beaconHash, record.us)) {
      ++beaconSuppressed;
    } else {
      record.seq = ++seen;
      PoolPush result = pool.push(record, record.bytes, record.len);
      if (result != PoolPush::Accepted) {
        ++dropped;
        if (result == PoolPush::RecordLimit) ++droppedRecords;
        else if (result == PoolPush::ByteLimit) ++droppedBytes;
        else ++droppedInvalid;
      } else if (record.headerOnly) {
        headerSampler.remember(record.beaconHash,record.us); ++headersQueued;
      } else if (beacon) {
        beaconSampler.remember(record.bytes+10, record.channel, record.beaconHash, record.us);
      }
    }
  }
  portEXIT_CRITICAL(&guard);
}
void wifiCallback(void* buffer, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  auto packet = static_cast<wifi_promiscuous_pkt_t*>(buffer);
  if (packet->rx_ctrl.rx_state) return;
  size_t len = type==WIFI_PKT_MGMT ? managementLength(packet->payload, packet->rx_ctrl.sig_len) : 0;
  bool headerOnly=!len;
  if (headerOnly) len=evidenceHeaderLength(packet->payload,packet->rx_ctrl.sig_len);
  if (!len) return;
  Record record{};
  record.us = now(); record.radio = 0;
  record.rssi = packet->rx_ctrl.rssi; record.channel = packet->rx_ctrl.channel;
  record.headerOnly=headerOnly;
  record.original = packet->rx_ctrl.sig_len-4; record.len = len < MAX_BYTES ? len : MAX_BYTES;
  memcpy(record.bytes, packet->payload, record.len);
  if (headerOnly) record.beaconHash=headerFingerprint(record.bytes,record.len,record.channel);
  else if (record.bytes[0] == 0x80) record.beaconHash = beaconFingerprint(packet->payload, len);
  enqueue(record);
}
class Callbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* device) override {
    Record record{};
    record.us = now(); record.radio = 1; record.rssi = device->getRSSI();
    record.addressType = device->getAddressType(); record.advType = device->getAdvType();
    auto address = device->getAddress();
    for (int i = 0; i < 6; ++i) record.mac[i] = address.getVal()[5-i];
    const auto& payload = device->getPayload();
    record.original = payload.size();
    record.len = payload.size() < MAX_BYTES ? payload.size() : MAX_BYTES;
    memcpy(record.bytes, payload.data(), record.len);
    enqueue(record);
  }
};
Callbacks callbacks;
void drain(unsigned limit, uint64_t budgetUs = 0) {
  Record record;
  const uint64_t started = now();
  // Check between complete packets: an individual serial write may block longer
  // under backpressure. A zero budget is reserved for the final stop drain.
  while (limit-- && (!budgetUs || now() - started < budgetUs)) {
    portENTER_CRITICAL(&guard);
    bool available = pool.pop(record, record.bytes, sizeof(record.bytes));
    portEXIT_CRITICAL(&guard);
    if (!available) break;
    header(record.radio ? "ble" : "wifi");
    Serial.printf(",\"seq\":%lu,\"capture_us\":%llu,\"sent_us\":%llu,\"rssi\":%d,\"original_length\":%u,\"truncated\":%s",
      (unsigned long)record.seq, record.us, now(), record.rssi, record.original,
      record.original > record.len ? "true" : "false");
    if (record.radio) {
      Serial.printf(",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"address_type\":%u,\"adv_type\":%u",
        record.mac[0],record.mac[1],record.mac[2],record.mac[3],record.mac[4],record.mac[5],record.addressType,record.advType);
    } else Serial.printf(",\"channel\":%u,\"frame_type\":\"%s\"", record.channel, record.headerOnly ? ((record.bytes[0]&12)==8 ? "data_header" : "management_header") : frameType(record.bytes));
    if (record.headerOnly) Serial.print(",\"header_only\":true");
    Serial.print(",\"payload\":\"");
    char hex[MAX_BYTES * 2 + 1];
    const char* digits = "0123456789abcdef";
    for (unsigned i=0; i<record.len; ++i) { hex[i*2]=digits[record.bytes[i]>>4]; hex[i*2+1]=digits[record.bytes[i]&15]; }
    hex[record.len*2]=0; Serial.print(hex); Serial.println("\"}");
  }
}
void health() {
  Serial.printf(",\"queue_capacity\":%u,\"queue_pool_bytes\":%u,\"queue_record_header_bytes\":%u,\"free_heap\":%lu,\"min_free_heap\":%lu,\"largest_free_block\":%lu,\"loop_stack_min_free\":%u",
    QUEUE_CAPACITY, (unsigned)POOL_BYTES, (unsigned)EvidencePool::HEADER_BYTES, (unsigned long)ESP.getFreeHeap(),
    (unsigned long)ESP.getMinFreeHeap(), (unsigned long)ESP.getMaxAllocHeap(),
    (unsigned)uxTaskGetStackHighWaterMark(nullptr));
}
void status() {
  uint32_t count, lost, suppressed, recordLost, byteLost, invalidLost;
  unsigned peak, queued, bytes, peakBytes;
  uint32_t hSeen,hSuppressed,hLimited,hQueued;
  portENTER_CRITICAL(&guard);
  count=seen; lost=dropped; suppressed=beaconSuppressed;
  hSeen=headersSeen; hSuppressed=headersSuppressed; hLimited=headersLimited; hQueued=headersQueued;
  recordLost=droppedRecords; byteLost=droppedBytes; invalidLost=droppedInvalid;
  queued=pool.count(); peak=pool.peakCount(); bytes=pool.used(); peakBytes=pool.peakBytes();
  portEXIT_CRITICAL(&guard);
  header("status");
  Serial.printf(",\"device_us\":%llu,\"seen\":%lu,\"dropped\":%lu,\"queued\":%u,\"beacon_suppressed\":%lu,\"queue_peak\":%u,\"queue_bytes\":%u,\"queue_bytes_peak\":%u,\"dropped_record_limit\":%lu,\"dropped_byte_limit\":%lu,\"dropped_invalid_length\":%lu",
    now(), (unsigned long)count, (unsigned long)lost, queued, (unsigned long)suppressed, peak, bytes, peakBytes,
    (unsigned long)recordLost, (unsigned long)byteLost, (unsigned long)invalidLost);
  Serial.printf(",\"headers_seen\":%lu,\"headers_suppressed\":%lu,\"headers_limited\":%lu,\"headers_queued\":%lu",
    (unsigned long)hSeen,(unsigned long)hSuppressed,(unsigned long)hLimited,(unsigned long)hQueued);
  health(); Serial.println("}");
}
void coverage(uint64_t end) {
  if (!windowOpen) return;
  windowOpen=false;
  header("coverage");
  Serial.printf(",\"radio\":\"%s\",\"channel\":%u,\"start_us\":%llu,\"end_us\":%llu}\n",
    bleWindow ? "BLE" : "WIFI", bleWindow ? 0 : CHANNELS[channelIndex], windowStart, end);
}
void acceptingSet(bool value) {
  portENTER_CRITICAL(&guard); accepting=value; portEXIT_CRITICAL(&guard);
}
void release() {
  acceptingSet(false);
  if (scan && bleReady) scan->stop();
  if (wifiReady) {
    esp_wifi_set_promiscuous(false); esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_stop(); esp_wifi_deinit(); wifiReady=false;
  }
  if (bleReady) {
    if (!wifi_scan_obj.resetBLEForEvidence()) { error("BLE shutdown failed; restarting to stop radio"); ESP.restart(); }
    bleReady=false; scan=nullptr;
  }
  wifi_scan_obj.wifi_initialized=false; wifi_scan_obj.ble_initialized=false;

}
void stop() {
  if (!running) return;
  uint64_t end=now();
  release(); coverage(end); drain(QUEUE_CAPACITY); status();
  running=false;
  header("stopped"); Serial.println("}");
}
bool wifiWindow() {
  if (esp_wifi_set_channel(CHANNELS[channelIndex], WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
  if (esp_wifi_set_promiscuous(true) != ESP_OK) return false;
  windowStart=now(); windowOpen=true; return true;
}
void start() {
  if (running) { error("Evidence capture is already running"); return; }
  if (wifi_scan_obj.currentScanMode != WIFI_SCAN_OFF || wifi_scan_obj.wifi_connected) {
    error("Stop other scans and disconnect Wi-Fi before evidence capture"); return;
  }
  if (!wifi_scan_obj.resetBLEForEvidence()) { error("Cannot reset BLE state"); return; }
  wifi_scan_obj.shutdownWiFi();
  portENTER_CRITICAL(&guard);
  accepting=false; pool.reset(); seen=0; dropped=0; beaconSuppressed=0;
  droppedRecords=0; droppedBytes=0; droppedInvalid=0;
  portEXIT_CRITICAL(&guard);
  beaconSampler.reset(); headerSampler.reset();
  headersSeen=headersSuppressed=headersLimited=headersQueued=0; stream=esp_random();
  channelIndex=0; bleWindow=false; windowOpen=false;
  wifi_init_config_t config=WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&config) != ESP_OK) { error("Wi-Fi initialization failed"); return; }
  wifiReady=true;
  wifi_promiscuous_filter_t filter{}; filter.filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  if (esp_wifi_set_storage(WIFI_STORAGE_RAM) != ESP_OK ||
      esp_wifi_set_mode(WIFI_MODE_NULL) != ESP_OK || esp_wifi_start() != ESP_OK ||
      esp_wifi_set_promiscuous_filter(&filter) != ESP_OK ||
      esp_wifi_set_promiscuous_rx_cb(wifiCallback) != ESP_OK) {
    release(); error("Cannot configure passive Wi-Fi capture"); return;
  }
  if (!NimBLEDevice::init("")) { release(); error("BLE initialization failed"); return; }
  bleReady=true; scan=NimBLEDevice::getScan();
  scan->setScanCallbacks(&callbacks, true); scan->setActiveScan(false);
  scan->setInterval(50); scan->setWindow(50); scan->setMaxResults(0); scan->setDuplicateFilter(0);
  if (!wifiWindow()) { release(); error("Cannot set passive Wi-Fi channel"); return; }
  running=true; acceptingSet(true); statusAt=now();
  header("started"); Serial.printf(",\"mode\":\"passive-2.4-ble\",\"max_payload\":1024,\"wifi_frame_types\":[\"probe_request\",\"beacon\",\"probe_response\",\"management_header\",\"data_header\"],\"header_sample_ms\":1000,\"header_rate_limit\":100,\"beacon_sample_ms\":5000,\"transport\":\"%s\"", TRANSPORT);
  health(); Serial.println("}");
}
}  // namespace
bool active() { return running; }
bool command(const String& input) {
  if (input.startsWith("evidence info ")) {
    String tx=input.substring(14);
    if (!tx.length() || tx.length()>40) return true;
    for (size_t i=0; i<tx.length(); ++i) if (!isAlphaNumeric(tx[i])) return true;
    Serial.printf("@WARD:{\"v\":1,\"event\":\"capabilities\",\"tx\":\"%s\",\"passive\":true,\"wifi_probe\":true,\"wifi_beacon\":true,\"wifi_probe_response\":true,\"wifi_headers\":true,\"ble_advertisement\":true}\n", tx.c_str());
    return true;
  }
  if (input=="evidence start") { start(); return true; }
  if (input=="evidence stop" || (running && input=="stopscan")) { stop(); return true; }
  if (running && input!="gps -g nmea" && !input.startsWith("protocolinfo ")) {
    error("Stop evidence capture before other commands"); return true;
  }
  return false;
}
void tick() {
  if (!running) return;
  // Bound each batch by elapsed time and count, then return to commands/GPS.
  drain(DRAIN_PACKET_LIMIT, DRAIN_BUDGET_US);
  uint64_t current=now();
  if (current-windowStart >= (bleWindow ? 500000 : 250000)) {
    acceptingSet(false);
    if (bleWindow) scan->stop(); else esp_wifi_set_promiscuous(false);
    coverage(now());
    bool ok;
    if (bleWindow) { bleWindow=false; channelIndex=0; ok=wifiWindow(); }
    else if (++channelIndex < sizeof(CHANNELS)) ok=wifiWindow();
    else {
      bleWindow=true; channelIndex=0;
      ok=scan->start(0, false, true); windowStart=now(); windowOpen=ok;
    }
    if (!ok) { error("Radio window transition failed"); stop(); return; }
    acceptingSet(true);
  }
  if (current-statusAt>=2000000) { status(); statusAt=current; }
}
}  // namespace passive_evidence
#endif
