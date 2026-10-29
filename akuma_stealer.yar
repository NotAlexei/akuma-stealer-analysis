/*
   Akuma Stealer (MaaS) - detection rules
   Source sample: AkumaClient_1.5.exe (Inno Setup 6.7.0 installer)
   SHA256 2fc54df0f35a045efd57210f36a5b0dc2c97804389eecbab36a27d4cdbafcabf
*/

import "hash"

rule Akuma_Stealer_Stub_Unpacked
{
    meta:
        description = "Akuma Stealer x64 stub after UPX removal: SysWhispers-style randomized indirect syscall stubs, DJB2 API/syscall hashing, rolling-XOR lazy string decryption"
        reference_sha256 = "1ad544b714bb08f232f36fe1310a3955d7793c2d90c3e753c5bee7aa814d701b"
    strings:
        // mov r10,rcx; mov r11,rdx; rdtsc; xor eax,edx; and eax,3Fh; lea rcx,[gadgets]; mov rcx,[rcx+rax*8]; mov rdx,r11; mov eax,[ssn]; xor eax,0B41FC435h; jmp rcx
        $sysstub = { 4C 8B D1 4C 8B DA 0F 31 33 C2 83 E0 3F 48 8D 0D ?? ?? ?? ?? 48 8B 0C C1 49 8B D3 8B 05 ?? ?? ?? ?? 35 35 C4 1F B4 FF E1 }
        // DJB2-XOR syscall-name hash: h=5381; h=h*33 ^ c
        $djb2x   = { C7 44 24 04 05 15 00 00 48 8B 44 24 08 80 38 00 74 ?? 8B 44 24 04 C1 E0 05 03 44 24 04 }
        // Lowercased DJB2 API-name hash: h=5381; h=h*33 + tolower(c)
        $djb2l   = { C7 44 24 04 05 15 00 00 C7 04 24 00 00 00 00 }
        // string decryptor key rotation: ror key,8 implemented as shr/shl 38h/or
        $strrot  = { 48 8B 44 24 30 48 C1 E8 08 48 8B 4C 24 30 48 C1 E1 38 48 09 C8 48 89 44 24 30 }
    condition:
        uint16(0) == 0x5A4D and
        #sysstub >= 10 and
        ($djb2x or $djb2l) and
        #strrot >= 50
}

rule Akuma_Stealer_Stub_UPX
{
    meta:
        description = "UPX-packed Akuma Stealer stub as shipped in the AkumaClient installer (platforms\\build.exe). Unpack with upx -d and use Akuma_Stealer_Stub_Unpacked for generic coverage."
        reference_sha256 = "f98805c06d7ca6e85a94ea629d905bf3940afd163c61ea096d70244af2d9eaa5"
    condition:
        uint16(0) == 0x5A4D and filesize < 300KB and
        hash.sha256(0, filesize) == "f98805c06d7ca6e85a94ea629d905bf3940afd163c61ea096d70244af2d9eaa5"
}

rule Akuma_Stealer_Panel
{
    meta:
        description = "AKUMA.exe - Akuma Stealer Qt6 operator panel / builder"
        reference_sha256 = "65a779808153b66a50962be8ee1e5354b50924358d289071e04c0726aae6af7e"
    strings:
        $c2      = "akumaqqq.xyz" ascii wide
        $tg1     = "t.me/AkumaManager" ascii wide
        $tg2     = "t.me/AkumaStealerInfo" ascii wide
        $bld1    = "-DP_ETWBYPASS=" ascii
        $bld2    = "-DCOMMAND_TO_ADD_AUTORUN=" ascii
        $bld3    = "-DBITCOIN_P2TR_ADDR=" ascii
        $bld4    = "cmd /c builder.bat " ascii
        $ui1     = "Crypto Clipper + Seeds Sniffer" ascii
        $ui2     = "ParametrForm" ascii
        $ui3     = "FormSeeds" ascii
    condition:
        uint16(0) == 0x5A4D and ($c2 or any of ($tg*)) and 2 of ($bld*, $ui*)
}

rule Akuma_Stealer_Inno_Installer
{
    meta:
        description = "Inno Setup installer distributing the Akuma Stealer panel (AkumaClient)"
        reference_sha256 = "2fc54df0f35a045efd57210f36a5b0dc2c97804389eecbab36a27d4cdbafcabf"
    strings:
        $inno = "Inno Setup Setup Data (6." ascii
        $ldr  = { 72 44 6C 50 74 53 CD E6 D7 7B 0B 2A }   // "rDlPtS" loader table ID
    condition:
        uint16(0) == 0x5A4D and $inno and $ldr and
        hash.sha256(0, filesize) == "2fc54df0f35a045efd57210f36a5b0dc2c97804389eecbab36a27d4cdbafcabf"
}
