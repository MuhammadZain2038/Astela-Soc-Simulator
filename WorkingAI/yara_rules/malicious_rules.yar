rule Suspicious_HTTP
{
    strings:
        $s1 = "GET /evil" nocase
        $s2 = "curl" nocase
    condition:
        any of them
}
