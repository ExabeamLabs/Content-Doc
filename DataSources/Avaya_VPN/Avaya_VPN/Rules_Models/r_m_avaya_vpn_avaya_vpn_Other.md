Vendor: Avaya VPN
=================
### Product: [Avaya VPN](../ds_avaya_vpn_avaya_vpn.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  25   |   10   |     5      |      5      |    5    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Models                                                                                                                                                                                                                                                                                                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| failed-vpn-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost-Failed</b>: User authentication or login failure from a known blacklisted IP<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>SEQ-UH-15</b>: Failed VPN login<br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity                                                                                                                                                                                                                                                                                                                                                                             |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity                                                                                                                                                                                                                                            |
| usb-insert       | <b>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User                                                                                                                                                                                |
| usb-read         | <b>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device<br><br><b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| usb-write        | <b>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device<br><br><b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| vpn-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP<br> ↳ <b>NEW-USER-F</b>: User with no event history<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization    |  • <b>UA-UC</b>: Countries for user activity<br> • <b>VPN-GsH</b>: VPN endpoints in this peer group<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>AE-UA</b>: All activity for users                                                                                           |