
rule Trojan_Adware_Generic_C
{
    meta:
        description = "Generic Trojan/Adware detection"
        author = "Scanner"
    strings:
        $adv1 = "adware" nocase
        $adv2 = "browser helper" nocase
        $adv3 = "inject" nocase
    condition:
        uint16(0) == 0x5A4D and any of ($adv*)
}
