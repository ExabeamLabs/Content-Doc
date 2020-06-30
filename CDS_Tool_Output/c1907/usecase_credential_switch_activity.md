Use Case: Credential Switch Activity
====================================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [Airlock](datasource_airlock_airlock.md)
* [Barracuda Firewall](datasource_barracuda_firewall_barracuda_firewall.md)
* [BeyondTrust PasswordSafe](datasource_beyondtrust_passwordsafe_beyondtrust_passwordsafe.md)
* [CA Privileged Access Manager Server Control](datasource_ca_privileged_access_manager_server_control_ca_privileged_access_manager_server_control.md)
* [CatoNetworks](datasource_catonetworks_catonetworks.md)
* [Centrify](datasource_centrify_centrify.md)
* [Check Point Security Gateway](datasource_check_point_security_gateway_check_point_security_gateway.md)
* [Cisco Adaptive Security Appliance](datasource_cisco_adaptive_security_appliance_cisco_adaptive_security_appliance.md)
* [Cisco AnyConnect](datasource_cisco_anyconnect_cisco_anyconnect.md)
* [Cisco ISE](datasource_cisco_ise_cisco_ise.md)
* [Cisco Meraki MX appliances](datasource_cisco_meraki_mx_appliances_cisco_meraki_mx_appliances.md)
* [CyberArk Privileged Session Manager](datasource_cyberark_privileged_session_manager_cyberark_privileged_session_manager.md)
* [CyberArk Vault](datasource_cyberark_vault_cyberark_vault.md)
* [Dell Quest TPAM](datasource_dell_quest_tpam_dell_quest_tpam.md)
* [Dropbox](datasource_dropbox_dropbox.md)
* [Fortinet VPN](datasource_fortinet_vpn_fortinet_vpn.md)
* [Palo Alto Networks GlobalProtect](datasource_globalprotect_palo_alto_networks_globalprotect.md)
* [Microsoft Windows](datasource_microsoft_windows_microsoft_windows.md)
* [Password Manager Pro](datasource_password_manager_pro_password_manager_pro.md)
* [Liebsoft](datasource_password_manager_liebsoft.md)
* [RSA SecurID](datasource_rsa_securid_rsa_securid.md)
* [Sonicwall](datasource_sonicwall_sonicwall.md)
* [Sophos](datasource_sophos_sophos.md)
* [Thycotic Secret Server](datasource_thycotic_secret_server_thycotic_secret_server.md)
* [Fox BoKS ServerControl](datasource_unix_fox_boks_servercontrol.md)
* [Unix](datasource_unix_unix.md)
* [Citrix Netscaler](datasource_vpn_citrix_netscaler.md)
* [Dell Aventail](datasource_vpn_dell_aventail.md)
* [F5 VPN](datasource_vpn_f5_vpn.md)
* [Juniper VPN](datasource_vpn_juniper_vpn.md)
* [NCP](datasource_vpn_ncp.md)
* [NetMotion Wireless](datasource_vpn_netmotion_wireless.md)
* [Nortel Contivity](datasource_vpn_nortel_contivity.md)
* [SSL Open VPN](datasource_vpn_ssl_open_vpn.md)
* [SecureNet](datasource_vpn_securenet.md)
* [Zscaler](datasource_vpn_zscaler.md)
* [Microsoft Windows](datasource_windows_microsoft_windows.md)


### Exabeam Event Types

- account-switch
- session-end
- vpn-logout
### Exabeam Content Library for this Use Case


_Rules_
- AS-HA-S : INTERNAL: The user that performs the account switch is a top account switcher on the host
- AS-PV-OG-F : First password retrieval activity for user in peer group
- AS-PV-OU-F : First password retrieval activity for user in organization
- AS-PV-US-A : Abnormal password retrieval using this safe value for user
- AS-PV-US-F : First password retrieval using this safe value for user
- AS-PV-USCOUNT-A : Abnormal number of password safes used by user
- AS-UA-A : Abnormal switch to target account for user
- AS-UA-F : First switch to target account for user
- AS-UA-FS : First account switch for user
- H-F : First password retrieval from asset for user
- UA-F-PRIV : Account switch to a privileged or executive account


_Exabeam Models_
- AS-HA : 
- AS-PV-OG : 
- AS-PV-OU : 
- AS-PV-US : 
- AS-PV-USCOUNT : 
- AS-PV-UsH : 
- AS-UA : 
- FACT : 
