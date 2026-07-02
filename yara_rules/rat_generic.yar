
rule RAT_Generic_C
{
    meta:
        description = "Generic RAT behavioral indicator"
        author = "Scanner"
    strings:
        $rat1 = "keylogger" nocase
        $rat2 = "remote access" nocase
        $rat3 = "socket" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($rat*)
}
