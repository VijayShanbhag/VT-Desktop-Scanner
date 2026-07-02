
rule Suspicious_PE_Structure_C
{
    meta:
        description = "Generic PE structure anomalies"
        author = "Scanner"
    strings:
        $s1 = "This program cannot be run in DOS mode"
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and $s1
}
