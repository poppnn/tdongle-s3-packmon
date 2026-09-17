# Serial console

Everything the button does — and more — can be driven from the USB serial port, so you can control
packmon from a laptop or phone terminal.

## Connecting

- **Baud:** 115200, 8-N-1 (line-based; send one command per line).
- **Port:** the dongle enumerates as a composite USB device — pick its **CDC serial** port
  (the other interface is the mass-storage drive, not a port).
  - Linux/macOS: `/dev/ttyACM*` or `/dev/tty.usbmodem*`
  - Windows: a `COMx` port labelled *USB Serial Device*
- Any terminal works: `pio device monitor`, `screen /dev/ttyACM0 115200`, PuTTY, the Arduino Serial
  Monitor, or a phone app like *Serial USB Terminal* (Android).

On boot the device prints `[poppn] serial console ready - type 'help'`. Type `help` and press Enter.

## Commands

| Command | What it does |
|---|---|
| `help` (or `?`) | list all commands |
| `status` | one-line summary: uptime, channel, packet/frame counts, deauth, EAPOL, networks, rate, page, SD and USB state, free heap |
| `page <arg>` | switch page. `<arg>` = a name (`live`, `channels`, `networks`, `threats`, `system`, `usb`), `next`, `prev`, or an index `0`–`5`. With no arg, prints the current page |
| `channel <1-13>` (or `ch`) | lock to a specific channel and stop hopping |
| `lock` | stop channel hopping on the current channel |
| `unlock` (or `hop`) | resume channel hopping |
| `nets` (or `networks`) | list discovered networks: SSID, BSSID, channel, RSSI, encryption |
| `threats` | list captured deauth/disassoc events with source/dest MAC, channel, RSSI, age |
| `reset` | clear all counters and tables |
| `usb on` | mount the SD card as a USB drive on the host (pauses logging) |
| `usb off` | eject the USB drive and resume logging |
| `sd` (or `log`) | logging / card status (session number, EAPOL and handshake counts) |
| `reboot` (or `restart`) | restart the device |

Commands are case-insensitive. Unknown input replies `unknown command '…' - type help`.

## Examples

```text
> status
status: up=142s ch=6(lock) pkts=48213 (mgmt=9120 ctrl=6034 data=33059 beacon=8871) deauth=2 eapol=4 aps=14 rate=412/s page=LIVE sd=on usb=idle heap=241184

> channel 6
ok: locked to channel 6

> nets
networks: 3
  HomeNet              AA:BB:CC:DD:EE:FF ch=6  rssi=-42  enc
  office-5G            11:22:33:44:55:66 ch=11 rssi=-63  enc
  <hidden>             77:88:99:AA:BB:CC ch=1  rssi=-70  open

> usb on
usb: mounted (logging paused)

> usb off
usb: ejected, logging resumed
```

## Notes

- `usb on` hands the card to the host, so logging is paused until you `usb off` (or eject from the
  host). Do not pull the card or power off while mounted.
- The 10-second `[stat] …` heartbeat still prints on its own; command replies are interleaved with it.
- The serial console is receive-and-report only — it never transmits WiFi frames.
