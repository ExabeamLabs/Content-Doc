Vendor: Microsoft
=================
Product: Microsoft Azure Active Directory
-----------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   0   |   0    |     0      |     11      |   11    |

|  Use-Case  | Event Types/Parsers    | MITRE TTP | Content    |
|:----------:| ---- | --------- | ---- |
| Enrichment |  account-password-change<br> ↳[cef-azure-auth-failed](Ps/pC_cefazureauthfailed.md)<br><br> account-unlocked<br> ↳[azure-ad-account-disabled](Ps/pC_azureadaccountdisabled.md)<br><br> app-activity<br> ↳[cef-azure-password-change](Ps/pC_cefazurepasswordchange.md)<br> ↳[azure-ad-account-password-change](Ps/pC_azureadaccountpasswordchange.md)<br> ↳[azure-ad-account-password-change-1](Ps/pC_azureadaccountpasswordchange1.md)<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br><br> app-activity-failed<br> ↳[azure-ad-app-login](Ps/pC_azureadapplogin.md)<br> ↳[s-azure-ad-password-change-2](Ps/pC_sazureadpasswordchange2.md)<br><br> app-login<br> ↳[azure-ad-app-login](Ps/pC_azureadapplogin.md)<br> ↳[s-azure-ad-app-login-2](Ps/pC_sazureadapplogin2.md)<br> ↳[s-azure-ad-app-login](Ps/pC_sazureadapplogin.md)<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br><br> dlp-email-alert-out<br> ↳[s-azure-ad-app-login-2](Ps/pC_sazureadapplogin2.md)<br> ↳[s-azure-ad-app-login](Ps/pC_sazureadapplogin.md)<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br><br> failed-app-login<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br><br> member-added<br> ↳[azure-ad-member-removed](Ps/pC_azureadmemberremoved.md)<br><br> process-created<br> ↳[azure-ad-account-unlocked](Ps/pC_azureadaccountunlocked.md)<br><br> security-alert<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br><br> usb-insert<br> ↳[azure-ad-member-added](Ps/pC_azureadmemberadded.md)<br> |    | [](RM/r_m_microsoft_microsoft_azure_active_directory_Enrichment.md) |

ATT&CK Matrix for Enterprise
----------------------------
