# Akuma Stealer — Indicators of Compromise

## Hashes (SHA-256)
```
2fc54df0f35a045efd57210f36a5b0dc2c97804389eecbab36a27d4cdbafcabf  AkumaClient_1.5.exe (installer)
65a779808153b66a50962be8ee1e5354b50924358d289071e04c0726aae6af7e  AKUMA.exe (panel)
f98805c06d7ca6e85a94ea629d905bf3940afd163c61ea096d70244af2d9eaa5  build.exe (stub, UPX, 2026-10-02)
1ad544b714bb08f232f36fe1310a3955d7793c2d90c3e753c5bee7aa814d701b  stub after upx -d
48e19794691a95f4b7a1f6b1726b5c2b02c5c4e1adf833ffebad20ad890af1bf  stub (UPX, 2026-10-29)
```

## Network
```
akumaqqq[.]xyz                                   C2 (Cloudflare-fronted)
hxxps://akumaqqq[.]xyz/api/Auth                  operator auth
hxxps://akumaqqq[.]xyz/api/DownloadFile          stub download
hxxps://akumaqqq[.]xyz/api/UploadFile?filename=  stub exfil (ZIP)
hxxps://akumaqqq[.]xyz/api/upSeeds?filename=     clipper/seed exfil
ipwho[.]is                                       geo lookup (benign service abused)
t[.]me/AkumaStealer_bot  t[.]me/AkumaManager  t[.]me/AkumaStealerInfo
UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Network pattern: POST to a .xyz host, filename=<digits>+...+None.zip
```

## Host
```
Mutex:    \BaseNamedObjects\JgDp3WxmN28sAvOGcWzWPs
Desktop:  WorkerDesktop
Run key:  HKCU\Software\Microsoft\Windows\CurrentVersion\Run  value "RtkAudUService64"
Startup:  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<random alnum>.exe
Install:  %ProgramFiles%\AkumaClient\  (AKUMA.exe, platforms\build.exe)
Classes:  Software\Classes\.myp, Software\Classes\AkumaClientFile.myp
Sandbox username blocklist: johndoe, hal9th
Geofence (exits): RU, BY, KZ
```

## Clipper wallet addresses (operator-controlled — substituted into clipboard)
```
BTC legacy   1G935gLHSub3TZWVppBXfDKW5cXCUD8qGb
BTC P2SH     3A6W8bdqvTeRktheVFXyLMA1PDtAqYU14R
BTC P2WPKH   bc1qtgpczqnd0r6gpp0atnt66cwllrx6qnl5nvrmyr
BTC P2WSH    bc1qpe2clnpnuv2gghyxpdu02gwx8svu4j90lelkeptapuc4ryet8tgse349xa
BTC P2TR     bc1pd3zq48rvr9ym72yku568z6y2t70a59j0270z68wjrfavxt3hh4hq4jtdsw
ETH          0x644b86E042F30D7c383acd217A0fAfB4969d279C
TRON         TXPVQAbAgeGXq6Jy16aGbsc7Fw2td9MvP4
TON          EQCABMVvavsgdTllIYk1lQDEeZRYDKwk5NukRazXA3u0bgsw
Solana       AagQNroMcpuKd3KDZVPFMUBUoiJYXBVGt6AH4nBeMVd
XRP          rHC1AENa2d8CyvEBZkC5URRidLnbyHbBVJ
Dogecoin     DCqziN9rfi5dhxN8K7ZaGNAJWP8eAT7DF6
BCH          bitcoincash:qrw53mag7ev6pydk4a64esqzmmarutsqcvug826lx5
```

## Fingerprints (build-stable)
```
SSN XOR key:          0xB41FC435
Indirect-syscall stub count: 29 Nt* stubs
API hashing:          lowercase DJB2 (h=5381; h=h*33+tolower(c))
Syscall-name hashing: DJB2-XOR     (h=5381; h=(h*33)^c)
```
