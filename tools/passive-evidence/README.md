# Passive evidence serial protocol v1

Transport: UART0 at 115200 8N1. One UTF-8 JSON object per line, prefixed `@WARD:`. Console chatter and GPS NMEA may be interleaved between complete lines. Payload bytes are hex encoded, so radio content cannot inject a console command or JSON line. The host retains the raw serial capture.

## Commands and lifecycle

- `protocolinfo --machine <tx>`: existing Marauder handshake.
- `evidence info <tx>`: returns `capabilities` with matching alphanumeric transaction, protocol `v:1`, and `passive`, `wifi_probe`, `ble_advertisement` booleans.
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
- `rssi`, `original_length`, `truncated`, `payload` (up to 384 bytes in hex).
- Wi-Fi: `channel`; payload is a probe-request management frame with ordinary 24-byte header, excluding the trailing FCS. Header+IE bytes permit independent host parsing. +HTC headers are excluded in v1.
- BLE: `mac` in display order, `address_type`, `adv_type`; payload is raw advertisement data delivered by NimBLE. Passive scanning does not request scan responses or discover unadvertised GATT services.

No OUI filter is applied on-device. Repeated observations are retained. The host refuses to promote truncated/malformed TLVs into a fingerprint match; it does not reconstruct missing fields to fit a signature.

## Coverage and health

The schedule is Wi-Fi channels `11,6,1,10,9,8,7,5,4,3,2`, targeting 250 ms per channel, followed by a 500 ms BLE window. The next cycle repeats. It does not survey 5 GHz. Serial backpressure can extend actual windows; `coverage` records the measured `start_us`/`end_us`, radio and channel. Transition gaps are not counted as coverage. These are receiver-enable intervals, not proof of lossless RF reception.

`status` reports `device_us`, `seen` (eligible packets offered to the queue), `dropped` (queue-full losses), and `queued`, approximately every two seconds and at stop. The 32-record queue is bounded. RF/controller losses before callbacks are unmeasured. Host status adds `host_sequence_gaps`, which overlaps device drops and must not be summed with them.

At 115200 baud the serial stream can saturate. Observe the counters before choosing a faster transport. No packet payload is written to SD by this new mode yet; the connected host is the recorder. The existing SD wardrive/PCAP modes remain separate.

## GPS and interpretation

The host continues checksum-valid NMEA queries. A packet may receive the latest fresh receiver position when the fix age is at most 12 seconds and firmware queue delay is at most two seconds. Its analysis records `gps_association.method=latest_host_fix` and fix age. This is approximate receiver location, not camera location or synchronized per-packet GNSS timing. No GPS fix is required to retain evidence.

Host evidence NDJSON includes original envelopes, parsed fields, rule version, match reasons, source links, and host receipt timestamps. Alerts group by radio/address, not asserted physical identity. BLE randomized addresses are not used for vendor-OUI claims.

Native boundary test: `c++ -std=c++17 -Wall -Wextra -Werror tools/passive-evidence/test_packet.cpp -o /tmp/passive-packet-test && /tmp/passive-packet-test`
