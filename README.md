# poppn packmon

WiFi packet monitor and deauthentication-attack detector for the **LilyGO T-Dongle S3**.

Plug it into any USB port and it becomes a standalone 802.11 monitor: it hops channels 1–13,
graphs live packet rate on the built-in 160×80 display, and raises a full-screen alert with the
attacker's MAC, channel and RSSI the moment it sees a deauth or disassoc frame.

**[→ Flash it from your browser](https://poppnn.github.io/tdongle-s3-packmon/)** — no toolchain needed.

---

## Features

- Promiscuous 802.11 capture on channels 1–13, hopping every 500 ms
- Five pages cycled with the dongle's own button — nothing to configure
- Deauth / disassoc detection: full-screen alert over any page, strobing LED, serial log
- Beacon parsing builds a live table of nearby networks (SSID, channel, encryption, RSSI)
- Per-channel activity bars so you can see which channel the noise is on
- Channel lock to stop hopping and stare at one channel
- APA102 status LED shifts colour with traffic load, red strobe under attack
- Rendered through a framebuffer at ~30 fps: no flicker, animated transitions throughout

## Pages

| Page | Shows |
|---|---|
| **LIVE** | packets/sec, total packets, deauth count, 30 s rate graph |
| **CHANNELS** | activity bar per channel 1–13, busiest channel and its share |
| **NETWORKS** | nearby APs sorted by signal — SSID, lock, channel, RSSI bars |
| **THREATS** | deauth total and the last three events with MAC, channel, RSSI, age |
| **SYSTEM** | uptime, packet total, network count, mgmt/data split, free RAM, fps |

Every page carries the current channel and live RSSI in its header.

## Controls

The dongle's BOOT button is the only control:

| Action | Effect |
|---|---|
| Tap | next page |
| Hold ~0.6 s | lock / unlock the current channel |
| Keep holding to 2.5 s | clear all counters and tables |

A progress bar along the bottom edge fills while you hold, so you can see which
threshold you are about to cross.

## Hardware

[LilyGO T-Dongle S3](https://github.com/Xinyuan-LilyGO/T-Dongle-S3) — ESP32-S3 USB dongle with an
ST7735 0.96" display, APA102 RGB LED and a microSD slot.

| Function | GPIO |
|---|---|
| Display MOSI | 3 |
| Display SCLK | 5 |
| Display CS | 4 |
| Display DC | 2 |
| Display RST | 1 |
| Backlight | 38 |
| LED data | 40 |
| LED clock | 39 |
| Button | 0 |

## Flashing

### Web flasher (easiest)

Open **<https://poppnn.github.io/tdongle-s3-packmon/>** in desktop Chrome, Edge or Opera
(Web Serial is not available in Firefox or Safari), hold **BOOT** while plugging the dongle in,
and click Install.

### From source

Requires [PlatformIO](https://platformio.org/).

```bash
git clone https://github.com/poppnn/tdongle-s3-packmon.git
cd tdongle-s3-packmon
pio run -t upload
pio device monitor
```

## Serial output

115200 baud over USB CDC. Every detection prints immediately:

```
[DEAUTH] #7  src=AA:BB:CC:DD:EE:FF  dst=FF:FF:FF:FF:FF:FF  ch=6  rssi=-42 dBm
```

and a heartbeat lands every 10 s, so a host can log the run without watching the screen:

```
[stat] pkts=48213 (mgmt=9120 ctrl=6034 data=33059 beacon=8871) deauth=0 aps=14 rate=412/s ch=9 dropped=0 heap=241184
```

## How it works

The promiscuous callback runs in the WiFi task and stays short: it bumps counters and pushes
richer frames (beacons, deauths) into a single-producer ring buffer. `loop()` drains that ring,
so the network and threat tables are only ever touched from one task and need no locking. If the
ring fills under heavy traffic, events are dropped rather than blocking the radio — the count
shows up as `dropped` in the heartbeat.

The UI draws into a 160×80 framebuffer (25 KB) and flushes it once per frame. That is what makes
animation possible at all: partial redraws straight to the panel flicker, a single flush does not.

A deauth frame takes over the screen for 5 s regardless of which page you are on, with a shrinking
bar showing when it will hand the page back.

## Rebuilding the web flasher image

The browser flasher serves a single merged image at offset `0x0`:

```bash
pio run
esptool.py --chip esp32s3 merge_bin -o docs/firmware/poppn-packmon.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0     .pio/build/lilygo-t-dongle-s3/bootloader.bin \
  0x8000  .pio/build/lilygo-t-dongle-s3/partitions.bin \
  0xe000  ~/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin \
  0x10000 .pio/build/lilygo-t-dongle-s3/firmware.bin
```

GitHub Pages serves `docs/` on the `main` branch.

## Legal

packmon is **receive-only**. It never transmits deauth frames or any other attack traffic — it only
listens and reports. Passive radio monitoring is nonetheless regulated in some jurisdictions: check
your local law, and only monitor networks you own or are authorised to test.

## Licence

MIT — see [LICENSE](LICENSE).
