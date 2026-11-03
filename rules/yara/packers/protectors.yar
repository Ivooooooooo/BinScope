/*
 * BinScope default protector signatures. Original rules, MIT.
 * These rules only report a marker; they do not assert the sample is malicious.
 */

rule binscope_protector_vmprotect
{
    meta:
        description = "VMProtect section names or marker"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "protector"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $marker = "VMProtect" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule binscope_protector_themida
{
    meta:
        description = "Themida/WinLicense marker"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "protector"
    strings:
        $a = "Themida" ascii
        $b = "WinLicense" ascii
        $c = ".themida" ascii
        $d = ".winlice" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule binscope_protector_enigma
{
    meta:
        description = "Enigma Protector section or marker"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "protector"
    strings:
        $a = ".enigma1" ascii
        $b = ".enigma2" ascii
        $c = "Enigma protector" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule binscope_protector_obsidium
{
    meta:
        description = "Obsidium protector marker"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "protector"
    strings:
        $a = ".obsidium" ascii
        $b = "Obsidium" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule binscope_protector_dotnet_reactor
{
    meta:
        description = "Possible .NET Reactor protected assembly"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "protector"
    strings:
        $bsjb = "BSJB" ascii
        $a = ".NET Reactor" ascii
        $b = "NETReactor" ascii
    condition:
        uint16(0) == 0x5A4D and $bsjb and any of ($a, $b)
}

rule binscope_protector_confuser
{
    meta:
        description = "Possible ConfuserEx obfuscated assembly"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "protector"
    strings:
        $bsjb = "BSJB" ascii
        $a = "ConfusedByAttribute" ascii
        $b = "ConfuserEx" ascii
    condition:
        uint16(0) == 0x5A4D and $bsjb and any of ($a, $b)
}
