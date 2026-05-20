# Wavlink WL-NU516U1 CVE Application Materials

## Common Fields
- Vendor: Wavlink
- Product: WL-NU516U1
- Version: M16U1_V240425
- Firmware Download: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A
- Advisory: https://github.com/Svigo-o/Wavlink_vul

---

## 1. GuestWifi Guest_password Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to GuestWifi, the function sub_4032E4 reads the Guest_password POST parameter via the URL decode function sub_405EA8. The decoded value is passed to sub_407504 (iwpriv_cmd) which constructs a shell command using sprintf("iwpriv %s set %s=\"%s\"", "rai1", "WPAPSK", user_input) and executes it via system(). The input filter sub_4074A0 only blocks backtick and pipe characters, but the $(cmd) command substitution syntax is not filtered, allowing arbitrary command execution. Authentication is not required. Conditions: guestEn=1 and Authentication_Mode=2.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-guestwifi-guestpassword-command-injection

---

## 2. DeleteMac delete_al_mac Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to DeleteMac, the function sub_402D1C reads the delete_al_mac POST parameter via the URL decode function sub_405EA8. The decoded value is concatenated into a shell command using sprintf("/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", delete_list, delete_al_mac, b_delete_list, b_delete_al_mac) and executed via the system() wrapper sub_405314. No input filter is applied in the DeleteMac handler. The $(cmd) command substitution syntax allows arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-deletealmac-command-injection

---

## 3. DeleteMac b_delete_list Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to DeleteMac, the function sub_402D1C reads the b_delete_list POST parameter via the URL decode function sub_405EA8. The decoded value is concatenated into a shell command using sprintf("/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", delete_list, delete_al_mac, b_delete_list, b_delete_al_mac) and executed via the system() wrapper sub_405314. No input filter is applied in the DeleteMac handler. The $(cmd) command substitution syntax allows arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-bdeletelist-command-injection

---

## 4. DeleteMac b_delete_al_mac Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to DeleteMac, the function sub_402D1C reads the b_delete_al_mac POST parameter via the URL decode function sub_405EA8. The decoded value is concatenated into a shell command using sprintf("/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", delete_list, delete_al_mac, b_delete_list, b_delete_al_mac) and executed via the system() wrapper sub_405314. No input filter is applied in the DeleteMac handler. The $(cmd) command substitution syntax allows arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-bdeletealmac-command-injection

---

## 5. SetName NewName Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to SetName, the function sub_403198 reads the NewName POST parameter via the URL decode function sub_405EA8. The decoded value is concatenated into a shell command using sprintf("/etc/lighttpd/www/cgi-bin/change_name.sh %s %s &", mac_5g, NewName) and executed via the system() wrapper sub_405314. No input filter is applied in the SetName handler. The $(cmd) command substitution syntax allows arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-setname-newname-command-injection

---

## 6. multi_ssid SSID2G2 Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to multi_ssid, the function sub_401D68 reads the SSID2G2 POST parameter via the URL decode function sub_405EA8. The decoded value is appended with "_Touch" and concatenated into shell commands using sprintf("set_bss.sh set 2 \"%s_Touch\" OPEN NONE Admin12345", ssid) and executed via system(). The input filter sub_4074A0 only blocks backtick and pipe characters, but the $(cmd) command substitution syntax is not filtered, allowing arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-ssid2g2-command-injection

---

## 7. multi_ssid SSID5G2 Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to multi_ssid, the function sub_401D68 reads the SSID5G2 POST parameter via the URL decode function sub_405EA8. The decoded value is appended with "_Touch" and concatenated into shell commands using sprintf("set_bss.sh set 2 \"%s_Touch\" OPEN NONE Admin12345", ssid) and executed via system(). The input filter sub_4074A0 only blocks backtick and pipe characters, but the $(cmd) command substitution syntax is not filtered, allowing arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-ssid5g2-command-injection

---

## 8. multi_ssid AuthMethod2 Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to multi_ssid, the function sub_401D68 reads the AuthMethod2 POST parameter via the URL decode function sub_405EA8. The decoded value is concatenated into shell commands using sprintf("set_bss.sh set 2 \"%s_Touch\" %s %s Admin12345", ssid, authmethod, encryptype) and executed via system(). The input filter sub_4074A0 only blocks backtick and pipe characters, but the $(cmd) command substitution syntax is not filtered, allowing arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-authmethod2-command-injection

---

## 9. multi_ssid WPAPSK12 Command Injection

**Class:** Command Injection

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a command injection vulnerability in /cgi-bin/wireless.cgi. When the page parameter is set to multi_ssid, the function sub_401D68 reads the WPAPSK12 POST parameter via the URL decode function sub_405EA8. The decoded value is concatenated into shell commands using sprintf("set_bss.sh set 2 \"%s_Touch\" %s %s %s", ssid, authmethod, encryptype, wpapsk) and executed via system(). The input filter sub_4074A0 only blocks backtick and pipe characters, but the $(cmd) command substitution syntax is not filtered, allowing arbitrary command execution.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-wpapsk12-command-injection

---

## 10. GuestWifi Guest_ssid Buffer Overflow

**Class:** Buffer Overflow

**Description:**
Wavlink WL-NU516U1 firmware M16U1_V240425 contains a stack-based buffer overflow vulnerability in /cgi-bin/wireless.cgi. The function sub_407504 (iwpriv_cmd) allocates a 1028-byte stack buffer and uses sprintf to construct a shell command: sprintf(v8[1028], "iwpriv %s set %s=\"%s\"", a1, a2, a3) without bounds checking. When the Guest_ssid POST parameter exceeds 998 bytes, the sprintf overflows the stack buffer and corrupts the saved return address ($ra register) on the MIPS architecture, potentially allowing control of program execution flow.

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-guestwifi-guestssid-buffer-overflow
