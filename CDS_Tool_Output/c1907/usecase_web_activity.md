Use Case: Web Activity
======================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [Apache](datasource_apache_apache.md)
* [Symantec](datasource_blue_coat_proxysg_appliance_symantec.md)
* [Bro](datasource_bro_bro.md)
* [CatoNetworks](datasource_catonetworks_catonetworks.md)
* [Check Point NGFW](datasource_check_point_ngfw_check_point_ngfw.md)
* [Cisco ADC](datasource_cisco_adc_cisco_adc.md)
* [Cisco Firepower](datasource_cisco_firepower_cisco_firepower.md)
* [Cisco Meraki MX appliances](datasource_cisco_meraki_mx_appliances_cisco_meraki_mx_appliances.md)
* [Cisco Umbrella](datasource_cisco_umbrella_cisco_umbrella.md)
* [Citrix Netscaler Web Logging](datasource_citrix_netscaler_web_logging_citrix_netscaler_web_logging.md)
* [Cloud Akamai](datasource_cloud_akamai_cloud_akamai.md)
* [Cloudflare](datasource_cloudflare_cloudflare.md)
* [Digital Arts](datasource_digital_arts_digital_arts.md)
* [Dtex](datasource_dtex_dtex.md)
* [EdgeWave](datasource_edgewave_edgewave.md)
* [F5](datasource_f5_f5.md)
* [FireEye Network Security (NX)](datasource_fireeye_network_security_(nx)_fireeye_network_security_(nx).md)
* [Forcepoint Web Security](datasource_forcepoint_web_security_forcepoint_web_security.md)
* [Fortinet UTM](datasource_fortinet_utm_fortinet_utm.md)
* [Gravityzone](datasource_gravityzone_gravityzone.md)
* [IBM](datasource_ibm_security_access_manager_ibm.md)
* [Imperva](datasource_imperva_incapsula_imperva.md)
* [InfoWatch](datasource_infowatch_infowatch.md)
* [Juniper Networks](datasource_juniper_srx_juniper_networks.md)
* [LanScope Cat](datasource_lanscope_cat_lanscope_cat.md)
* [LanScope](datasource_lanscope_lanscope.md)
* [McAfee Web Gateway](datasource_mcafee_web_gateway_mcafee_web_gateway.md)
* [Microsoft Azure EventHub](datasource_microsoft_azure_eventhub_microsoft_azure_eventhub.md)
* [Microsoft IIS](datasource_microsoft_iis_microsoft_iis.md)
* [Microsoft Sharepoint](datasource_microsoft_sharepoint_microsoft_sharepoint.md)
* [Microsoft Web Application Proxy-TLS Gateway](datasource_microsoft_web_application_proxy-tls_gateway_microsoft_web_application_proxy-tls_gateway.md)
* [Microsoft Web Application Proxy](datasource_microsoft_web_application_proxy_microsoft_web_application_proxy.md)
* [Microsoft IIS](datasource_microsoft_microsoft_iis.md)
* [Mimecast](datasource_mimecast_mimecast.md)
* [NGINX](datasource_nginx_nginx.md)
* [Netskope Active Platform](datasource_netskope_active_platform_netskope_active_platform.md)
* [Palo Alto Networks NGFW](datasource_palo_alto_networks_ngfw_palo_alto_networks_ngfw.md)
* [Ping Identity](datasource_ping_identity_ping_identity.md)
* [SIGSCI](datasource_sigsci_sigsci.md)
* [Sangfor NGAF](datasource_sangfor_ngaf_sangfor_ngaf.md)
* [SentinelOne](datasource_sentinelone_sentinelone.md)
* [SkySea ClientView](datasource_skysea_clientview_skysea_clientview.md)
* [Sophos UTM](datasource_sophos_utm_sophos_utm.md)
* [Squid](datasource_squid_squid.md)
* [Symantec Blue Coat ProxySG Appliance](datasource_symantec_blue_coat_proxysg_appliance_symantec_blue_coat_proxysg_appliance.md)
* [Symantec Fireglass](datasource_symantec_fireglass_symantec_fireglass.md)
* [Symantec Secure Web Gateway](datasource_symantec_secure_web_gateway_symantec_secure_web_gateway.md)
* [Symantec WSS](datasource_symantec_wss_symantec_wss.md)
* [TFCS](datasource_tfcs_tfcs.md)
* [HashiCorp](datasource_terraform_hashicorp.md)
* [Cisco Web Security Appliance](datasource_threat_cisco_web_security_appliance.md)
* [Trend Micro InterScan Web Security](datasource_trend_micro_interscan_web_security_trend_micro_interscan_web_security.md)
* [Juniper VPN](datasource_vpn_juniper_vpn.md)
* [Watchguard](datasource_watchguard_watchguard.md)
* [Cisco Cloud Web Security](datasource_web_proxy_cisco_cloud_web_security.md)
* [IronPort Web Security](datasource_web_proxy_ironport_web_security.md)
* [Weblogin](datasource_weblogin_weblogin.md)
* [Websense](datasource_websense_websense.md)


### Exabeam Event Types

- sequence-end
- web-activity-allowed
- web-activity-denied
### Exabeam Content Library for this Use Case


_Rules_
- A-FS : Abnormal amount of data for peer group has been uploaded to a file sharing site
- A-FS : Abnormal amount of data for user has been uploaded to a file sharing site
- A-JS : Abnormal amount of data had been uploaded to a job search site for the user
- A-JS : Abnormal amount of data had been uploaded to a job search site in the peer group
- A-WEB-ALERT : Asset attempted access to a domain with malicious reputation
- A-WEB-DC : Web activity event on a Domain Controller
- A-WEB-DGA : Asset has accessed a domain that has been identified as DGA
- A-WEB-DLP-A : Possible data exfiltration: Abnormal amount of data had been uploaded to the web from this asset
- A-WEB-HA-F : First web activity event on asset
- A-WEB-IOC : Indicator of Compromise (IOC) found in asset's web activity
- A-WEB-IP : Asset has browsed to an IP address instead of a domain name
- A-WEB-IP-F : First time asset has browsed directly to this IP address.
- FS-PU : Abnormal amount of data had been downloaded from file sharing websites by privileged user
- NEW-USER-WEB : INTERNAL: New user with no web-activity history.
- OS-F : First web activity using this operating system for the organization
- OS-F : First web activity using this operating system for the peer group
- OS-F : First web activity using this operating system for this user
- WEB-FILE : INTERNAL: User has accessed a file sharing domain
- WEB-FS : User has accessed a file sharing domain
- WEB-GZ-F : First web activity from this zone for the peer group
- WEB-IOC : Indicator of Compromise (IOC) found in user's web activity
- WEB-IP-F : First time user has browsed directly to this IP address
- WEB-JOB : INTERNAL: User has accessed a job search domain
- WEB-JS : User has accessed a job search domain
- WEB-OC-F : First access to an internet IP address in this country for the organization
- WEB-OG-FS : One of the top file sharing users in the peer group
- WEB-OG-JS-A : Abnormal job search activity for user in the peer group
- WEB-OG-JS-F : First job search activity for user in the peer group
- WEB-OU-FS : One of the top file sharing users in the organization
- WEB-OU-JS-A : Abnormal job search activity for user in the organization
- WEB-OU-JS-F : First job search activity for user in the organization
- WEB-OZ-F : First web activity from this zone for the organization
- WEB-UC-A : Abnormal access to an internet IP address in this country
- WEB-UC-F : First access to an internet IP address in this country
- WEB-UD-ALERT : INTERNAL: Web Alert Match
- WEB-UD-ALERT-A : Abnormal security alert accessing this malicious domain for user
- WEB-UD-ALERT-F : First security alert accessing this malicious domain for user
- WEB-UD-ALERT-N : Common security alert on this malicious domain for user
- WEB-UD-DGA : INTERNAL: User has accessed a domain that was been identified as DGA
- WEB-UD-DGA-A : Abnormal access to this domain which has been identified as DGA
- WEB-UD-DGA-F : First access to this domain which has been identified as DGA
- WEB-UD-DGA-N : Common access to this domain which has been identified as DGA
- WEB-UD-F : INTERNAL: first time access to a web domain for the user
- WEB-UDLP-A : Possible data exfiltration: Abnormal amount of data had been uploaded to the web
- WEB-UDLP-A-FS : Abnormal amount of data for organization has been uploaded to a file sharing site
- WEB-UDLP-A-JS : Abnormal amount of data had been uploaded to a job search site in the organization
- WEB-UGETDLP-A : Possible data exfiltration: Abnormal amount of data had been written to the web in http GET requests
- WEB-UT-TOW-A : Abnormal day for this user to access the web via the organization
- WEB-UZ-F : First web activity for this user in this zone
- WEB-ZU : INTERNAL: Zone is not new OR it has converged for web activity


_Exabeam Models_
- A-WEB-BytesSum-Out : 
- A-WEB-HA : Web activity per Host
- A-WEB-IP : IPs an asset has directly browsed to
- FACT : 
- WEB-GBytesSum-Out-FS : 
- WEB-GBytesSum-Out-JS : 
- WEB-GUa-OS : 
- WEB-GZ : 
- WEB-IP : 
- WEB-OBytesSum-Out-FS : 
- WEB-OBytesSum-Out-JS : 
- WEB-OC : 
- WEB-OG-FS : 
- WEB-OG-JS : 
- WEB-OU-FS : 
- WEB-OU-JS : 
- WEB-OUa-OS : 
- WEB-OZ : 
- WEB-UBytesSum-In-FS-PU : 
- WEB-UBytesSum-Out : 
- WEB-UBytesSum-Out-FS : 
- WEB-UBytesSum-Out-JS : 
- WEB-UC : 
- WEB-UD-ALERT : 
- WEB-UD-DGA : 
- WEB-UGETBytes-Out : 
- WEB-UT-TOW : 
- WEB-UTD : 
- WEB-UUa-OS : 
- WEB-UZ : 
- WEB-ZU : 
