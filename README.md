# Akuma Stealer — reverse-engineering writeup & detection

Static analysis of **Akuma Stealer**, a Malware-as-a-Service (MaaS) Windows infostealer sold via
Telegram, based on its operator installer `AkumaClient_1.5.exe` and two stealer stubs.

Virustotal: https://www.virustotal.com/gui/file-analysis/YjhhMjM5ODM5OTYzMzYyM2M5ZmQ2MTExZDUzNjJiOTI6MTc5MzMxNzExOQ==

Malwarebazaar: https://bazaar.abuse.ch/sample/48e19794691a95f4b7a1f6b1726b5c2b02c5c4e1adf833ffebad20ad890af1bf/

## TL;DR

`AkumaClient_1.5.exe` is an Inno Setup 6.7.0 installer for the **operator side** of Akuma Stealer.
It ships a Qt6 operator panel/builder (`AKUMA.exe`), a configured test stub, and runtime DLLs. The
dangerous payload is the **stub**: a UPX-packed x64 MSVC binary with OLLVM-style obfuscation,
per-string encryption, DJB2-hashed dynamic API resolution, and SysWhispers-style randomized
indirect syscalls. It steals browser credentials/cookies/cards, crypto wallets (desktop +
extensions) and seed phrases, messaging/gaming tokens, and corporate/SSH/VPN secrets, then exfils a
ZIP over HTTPS to a Cloudflare-fronted C2. A resident clipper swaps copied wallet addresses for the
operator's.

## Samples

| File | SHA-256 | Notes |
|---|---|---|
| AkumaClient_1.5.exe (installer) | `2fc54df0f35a045efd57210f36a5b0dc2c97804389eecbab36a27d4cdbafcabf` | Inno Setup 6.7.0 |
| AKUMA.exe (panel) | `65a779808153b66a50962be8ee1e5354b50924358d289071e04c0726aae6af7e` | MinGW/Qt6, PE ts 2026-10-02 |
| build.exe (stub, UPX) | `f98805c06d7ca6e85a94ea629d905bf3940afd163c61ea096d70244af2d9eaa5` | configured test build |
| stub (UPX, newer build) | `48e19794691a95f4b7a1f6b1726b5c2b02c5c4e1adf833ffebad20ad890af1bf` | PE ts 2026-10-29 |

## Stub protection layers

1. **UPX** — removes cleanly with `upx -d` (or emulate the stub to dump; see below).
2. **OLLVM-style obfuscation** — mixed boolean-arithmetic opaque predicates over stack seeds.
3. **Per-string encryption** — each string has its own accessor with a 64-bit key, rolling-XOR
   (`out[i] = in[i] ^ (key & 0xFF)`, key rotated right 8 bits per char; byte and UTF-16 variants),
   a lazy "decrypted" flag, and an `atexit` wipe. The Oct-2 build has **911** such strings; all
   were recovered by CPU emulation (see `iocs/stub_decrypted_strings.tsv`). The Oct-29 build uses a
   revised lazy-static accessor scheme (~482 strings) — the operator is actively re-obfuscating.
4. **Dynamic API resolution** — PEB walk + export lookup by **lowercase DJB2**
   (`h=5381; h=h*33+tolower(c)`), so no hash constants sit on disk.
5. **Indirect syscalls (SysWhispers2/3 "randomized jumper")** — 29 `Nt*` stubs; SSNs matched by
   **DJB2-XOR** (`h=5381; h=(h*33)^c`), stored XOR `0xB41FC435`; each call jumps to one of ≤64
   `syscall; ret` gadgets picked by `rdtsc`. The `0xB41FC435` constant + the 29-stub count are a
   reliable fingerprint across builds.

## Execution flow (stub)

1. Build API + syscall tables (ntdll resolved first via `RtlAllocateHeap`).
2. **Anti-debug (always on):** `NtSetInformationThread(ThreadHideFromDebugger)`, debug-register
   check, `NtQueryInformationProcess` (DebugPort/DebugObjectHandle/DebugFlags).
3. Optional anti-VM (CPUID hypervisor vendor, core/RAM metrics, SMBIOS/firmware, VM driver files,
   cursor movement) — configurable per build. EDR/AV inventory by driver name.
4. **Sandbox username blocklist** (`johndoe`, `hal9th`).
5. **CIS geofence** — exits on `RU`/`BY`/`KZ` (keyboard layout + `ipwho.is` country code).
6. Single-instance mutex (`NtCreateMutant`).
7. **Chromium App-Bound Encryption (v20) bypass:** creates a hidden desktop `WorkerDesktop`,
   launches the browser with `--no-first-run https://www.google.com`, reads its memory
   (`chrome_elf.dll`/`msedge_elf.dll`) to recover the decrypted key, then kills it. v10/v11 secrets
   via DPAPI on `Local State` `encrypted_key`; AES-GCM via BCrypt.
8. **Collection:** Chromium + Firefox logins/cookies/cards/history (via `sqlite3_deserialize` on
   in-memory copies to dodge file locks); 68 wallet-extension IDs and a dozen desktop wallets;
   Telegram `tdata`, Discord tokens, Steam, Rockstar, Epic, Battle.net, Riot, EA, Roblox, Minecraft;
   AWS/Azure/GCloud/GitHub-CLI/kube/SSH; password managers; VPNs; FileZilla; a file grabber by
   extension; and a system profile (HWID, OS, product key, EDR list, IP geo).
9. **Exfiltration** and **persistence** (Run key + Startup copy) — see C2 section.
10. **Clipper + seed sniffer:** clipboard listener swaps wallet addresses for the operator's;
    scans `.log`/`.ldb` (LevelDB) for seed/session material.

## C2 protocol (`akumaqqq.xyz`, Cloudflare-fronted)

Subscription MaaS backend with two client types.

**Operator (panel, authenticated):**
- `POST /api/Auth` — `login`+`password` → session `token` + `date_end` (subscription expiry; panel
  refuses expired/unparseable dates).
- `/api/Build…` — submit the `-D` build config; `/api/DownloadFile` — fetch compiled stub;
  `/api/get…` — pull stolen logs/seeds. Token sent in `Authorization` header.

**Victim (stub, anonymous, one-way):**
- `POST /api/UploadFile?filename=<P_LOGIN>+<host bits>+None.zip` — octet-stream ZIP of stolen data.
- `POST /api/upSeeds?filename=<random>.zip` — clipper/seed material.
- The `filename`'s leading `P_LOGIN` is the customer id the backend files loot under. No tasking
  channel back (stealer, not RAT).

**Transport:** WinHTTP, spoofed Chrome UA, HTTPS:443 with certificate validation disabled
(`WINHTTP_OPTION_SECURITY_FLAGS = 0x3300`).

**Infrastructure (public records):** `.xyz` registered 2026-06-14 via OwnRegistrar, Inc.;
Cloudflare nameservers; only Cloudflare edge certs (Let's Encrypt / Google Trust) in CT — no origin
leak.

## Unpacking tip (no UPX binary required)

The stub's UPX layer can be removed by emulating the stub with [Unicorn]: map the image, point the
IAT thunks at catchable fake addresses, run from the entry point, and stop at the first
`LoadLibraryA` call (UPX decompresses fully *before* rebuilding imports) — then dump the image. The
decompressed code still has the per-string encryption layer intact.

## Detection

- **YARA:** [`akuma_stealer.yar`](akuma_stealer.yar) — unpacked-stub (syscall/DJB2/string-rot byte
  patterns), packed stub (hash), panel, and installer rules.
- **Behavioral:** non-browser process creating a desktop named `WorkerDesktop`; a browser launched
  `--no-first-run https://www.google.com` by an unsigned parent; cross-process `NtReadVirtualMemory`
  into a browser; indirect syscalls (return address in ntdll, caller outside it); a clipboard
  listener plus a Run value named `RtkAudUService64`; `winsqlite3.dll` loaded by a non-system
  binary; outbound `ipwho.is` followed by a POST to `/api/UploadFile`.
- **Network:** POST to a `.xyz` host with `filename=<digits>+…+None.zip`.

See [`iocs/indicators.md`](iocs/indicators.md) for the full indicator list.

## If a stub ran

Treat the machine as fully credential-compromised: rotate all browser-saved passwords/sessions,
move crypto funds and treat seeds as burned, rotate Discord/Telegram/Steam/game and Windows
credentials, remove the Run value and Startup copy, and check recent clipboard-pasted crypto
transactions for substituted addresses.

## Credits

Static RE + emulation tooling (Python `pefile`/`capstone`/`unicorn`). Analysis assisted by
Claude Code. Samples available on MalwareBazaar.

[Unicorn]: https://www.unicorn-engine.org/
