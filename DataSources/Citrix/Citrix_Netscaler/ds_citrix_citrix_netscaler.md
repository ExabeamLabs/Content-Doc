Vendor: Citrix
==============
Product: Citrix Netscaler
-------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   0   |   0    |     0      |      7      |    7    |

|  Use-Case  | Event Types/Parsers    | MITRE TTP | Content    |
|:----------:| ---- | --------- | ---- |
| Enrichment |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> |    | [](RM/r_m_citrix_citrix_netscaler_Enrichment.md) |

ATT&CK Matrix for Enterprise
----------------------------
