# Wavlink_WLNU516_vul

Wavlink WL-NU516U1 路由器漏洞挖掘与验证分析记录。

固件版本: M16U1_V240425

固件下载: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A

目标二进制: /cgi-bin/wireless.cgi

分析工具: IDA MCP (Hex-Rays 反编译) + 源码审计

## 漏洞列表

| 目录 | 接口/功能 | 函数 | 参数 | 类型 | CVE |
| --- | --- | --- | --- | --- | --- |
| [wavlink-wl-nu516u1-wireless-guestwifi-guestpassword-command-injection](wavlink-wl-nu516u1-wireless-guestwifi-guestpassword-command-injection) | GuestWifi / `sub_4032E4` | `sub_407504` | `Guest_password` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-deletemac-deletealmac-command-injection](wavlink-wl-nu516u1-wireless-deletemac-deletealmac-command-injection) | DeleteMac / `sub_402D1C` | `del_mac.sh` | `delete_al_mac` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-deletemac-bdeletelist-command-injection](wavlink-wl-nu516u1-wireless-deletemac-bdeletelist-command-injection) | DeleteMac / `sub_402D1C` | `del_mac.sh` | `b_delete_list` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-deletemac-bdeletealmac-command-injection](wavlink-wl-nu516u1-wireless-deletemac-bdeletealmac-command-injection) | DeleteMac / `sub_402D1C` | `del_mac.sh` | `b_delete_al_mac` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-setname-newname-command-injection](wavlink-wl-nu516u1-wireless-setname-newname-command-injection) | SetName / `sub_403198` | `change_name.sh` | `NewName` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-multissid-ssid2g2-command-injection](wavlink-wl-nu516u1-wireless-multissid-ssid2g2-command-injection) | multi_ssid / `sub_401D68` | `set_bss.sh` | `SSID2G2` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-multissid-ssid5g2-command-injection](wavlink-wl-nu516u1-wireless-multissid-ssid5g2-command-injection) | multi_ssid / `sub_401D68` | `set_bss.sh` | `SSID5G2` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-multissid-authmethod2-command-injection](wavlink-wl-nu516u1-wireless-multissid-authmethod2-command-injection) | multi_ssid / `sub_401D68` | `set_bss.sh` | `AuthMethod2` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-multissid-wpapsk12-command-injection](wavlink-wl-nu516u1-wireless-multissid-wpapsk12-command-injection) | multi_ssid / `sub_401D68` | `set_bss.sh` | `WPAPSK12` | Command Injection | TBD |
| [wavlink-wl-nu516u1-wireless-guestwifi-guestssid-buffer-overflow](wavlink-wl-nu516u1-wireless-guestwifi-guestssid-buffer-overflow) | GuestWifi / `sub_4032E4` | `sub_407504` | `Guest_ssid` | Buffer Overflow | TBD |

## 输入过滤机制

`sub_4074A0` 对 iwpriv 命令进行字符级过滤：

| 字符 | ASCII | 是否过滤 | 绕过方式 |
|------|-------|----------|----------|
| `` ` `` | 96 | 过滤 | 使用 `$()` |
| `\|` | 124 | 过滤 | 使用 `;` 或 `&&` |
| `$()` | - | **未过滤** | 直接使用 |
| `;` | - | **未过滤** | 直接使用 |
| `&&` | - | **未过滤** | 直接使用 |
