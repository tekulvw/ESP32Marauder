# Passive evidence serial protocol v1

Transport: native USB Serial/JTAG CDC when built with CDC-on-boot enabled, otherwise UART0 at 115200 8N1. Native USB still uses a serial device API, but its data rate is not limited by the nominal baud value. The `started.transport` field records `usb_serial_jtag` or `uart0`. One UTF-8 JSON object per line, prefixed `@WARD:`. Console chatter and GPS NMEA may be interleaved between complete lines. Payload bytes are hex encoded, so radio content cannot inject a console command or JSON line. The host retains the raw serial capture.

## Commands and lifecycle

- `protocolinfo --machine <tx>`: existing Marauder handshake.
- `evidence info <tx>`: returns `capabilities` with matching alphanumeric transaction, protocol `v:1`, and `passive`, `wifi_probe`, `wifi_beacon`, `wifi_probe_response`, `ble_advertisement` booleans. Older v1 builds omit the two AP capabilities. The `started` event persists `wifi_frame_types`, `max_payload:1024` and `beacon_sample_ms:5000` so hosts can describe actual session coverage. Update the host before installing this firmware; old hosts accept only 384-byte packets.
- `evidence start`: requires other scans/Wi-Fi connections stopped. Returns `started` after receive paths initialize. No automatic fallback to `wardrive`.
- `evidence stop`: stops receiving, reports the last coverage interval, drains the bounded queue, emits final status, then `stopped`.
- `stopscan`: also stops evidence when active.
- During capture only the exact GPS query `gps -g nmea`, the handshake, and evidence commands are accepted. Other commands cannot switch radio modes underneath a recording.

All capture events carry `v:1`, `event`, and an eight-hex-digit `stream` created at start. A changed stream or backward/repeated packet sequence is an error. Firmware errors carry a `message`. This is a single serial-owner prototype, not an authenticated network protocol.

## Packet events

`wifi` / `ble` carry:

- `seq`: shared packet counter, starting at 1, allocated before queue admission; gaps expose dropped packets. Counter is 32-bit; host errors rather than silently accepting wrap.
- `capture_us`: 64-bit device monotonic callback timestamp; not UTC and not the exact over-the-air timestamp.
- `sent_us`: device timestamp immediately before serializing the remaining event.
- `rssi`, `original_length`, `truncated`, `payload` (up to 1024 bytes in hex).
- Wi-Fi: `channel`, `frame_type` (`probe_request`, `beacon`, `probe_response`); payload is a management frame with ordinary 24-byte header, excluding the trailing FCS. Beacons/responses include 12 fixed bytes before their IEs: 8-byte TSF, 2-byte beacon interval and 2-byte capability flags, little-endian. Protected, fragmented, nonzero-version and +HTC frames are excluded. The host cross-checks the frame-type label against raw bytes and can infer the type for older envelopes.
- BLE: `mac` in display order, `address_type`, `adv_type`; payload is raw advertisement data delivered by NimBLE. Passive scanning does not request scan responses or discover unadvertised GATT services.

No OUI filter is applied on-device. Probe requests, probe responses and BLE advertisements are retained subject to queue capacity. Repeated beacon content is sampled at most once per transmitter/channel/content hash per five seconds using a bounded 128-entry cache. Previously unseen content variants bypass that interval; the hash excludes TSF, sequence/retry fields and volatile TIM IEs, which are still retained in the emitted payload. A 32-bit hash collision can suppress a changed beacon until the interval expires. Cache eviction can admit more repeats. Only successfully queued packets update the cache, so queue loss does not suppress the next retry. RSSI changes alone do not bypass sampling. The host refuses to promote truncated/malformed TLVs into a fingerprint match; it does not reconstruct missing fields to fit a signature.

## Coverage and health

The schedule is Wi-Fi channels `11,6,1,10,9,8,7,5,4,3,2`, targeting 250 ms per channel, followed by a 500 ms BLE window. The next cycle repeats. It does not survey 5 GHz. Serial backpressure can extend actual windows; `coverage` records the measured `start_us`/`end_us`, radio and channel. Transition gaps are not counted as coverage. These are receiver-enable intervals, not proof of lossless RF reception.

`status` reports `device_us`, `seen` (packets offered to the queue after beacon sampling), `dropped` (queue-full losses), `queued`, and `beacon_suppressed` (deliberately sampled repeats), approximately every two seconds and at stop. The queue is bounded at 40 records on native USB, and 32 on UART to keep the stop tail within the host deadline. New `started` and `status` events advertise `queue_capacity` and `queue_record_bytes` (the actual slot size including metadata/padding). `status.queue_peak` is the highest occupancy since capture start. `free_heap` and `largest_free_block` describe current internal heap bytes; `min_free_heap` is the internal heap low-water mark since boot, not just this capture. `loop_stack_min_free` is the Arduino loop task's minimum unused stack bytes since task creation (ESP-IDF reports bytes). These are sampled outside radio callbacks; the final status is after radio teardown and may have more free heap than active capture. Update the host before using the larger queue: older hosts reject `queued` above 32. Hosts retain compatibility with older firmware that omits capacity (32 assumed). RF/controller losses before callbacks are unmeasured. Host status adds `host_sequence_gaps`, which overlaps device drops and must not be summed with them.

At 115200 baud the UART stream can saturate. The project native-USB build uses a 4096-byte TX and 1024-byte RX ring buffer. C5 USB owns GPIO13/14, so this build moves GPS TX -> C5 GPIO4 (RX) and GPS RX <- C5 GPIO5 (TX); physically rewire those signals with power removed. UART-only builds retain the original GPS GPIO14/13 mapping. Observe the counters before choosing a faster transport. No packet payload is written to SD by this new mode yet; the connected host is the recorder. The existing SD wardrive/PCAP modes remain separate.

## GPS and interpretation

The host continues checksum-valid NMEA queries. A packet may receive the latest fresh receiver position when the fix age is at most 12 seconds and firmware queue delay is at most two seconds. Its analysis records `gps_association.method=latest_host_fix` and fix age. This is approximate receiver location, not camera location or synchronized per-packet GNSS timing. No GPS fix is required to retain evidence.

Host evidence NDJSON includes original envelopes, parsed fields, rule version, match reasons, source links, and host receipt timestamps. Alerts group by radio/address, not asserted physical identity. BLE randomized addresses are not used for vendor-OUI claims.

Native boundary test: `c++ -std=c++17 -Wall -Wextra -Werror tools/passive-evidence/test_packet.cpp -o /tmp/passive-packet-test && /tmp/passive-packet-test`
