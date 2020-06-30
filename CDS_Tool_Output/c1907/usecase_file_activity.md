Use Case: File Activity
=======================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [AD Audit](datasource_ad_audit_ad_audit.md)
* [AWS](datasource_aws_cloudtrail_aws.md)
* [AWS CloudTrail](datasource_aws_cloudtrail_aws_cloudtrail.md)
* [Airlock](datasource_airlock_airlock.md)
* [AssetView](datasource_assetview_assetview.md)
* [BitGlass](datasource_bitglass_bitglass.md)
* [Box](datasource_box_box.md)
* [Bro](datasource_bro_bro.md)
* [Bromium Secure Platform](datasource_bromium_secure_platform_bromium_secure_platform.md)
* [BusinessObject](datasource_businessobject_businessobject.md)
* [Carbon Black](datasource_carbon_black_carbon_black.md)
* [Carbon Black Defense](datasource_cb_defense_carbon_black_defense.md)
* [Carbon Black Protection](datasource_cb_protection_carbon_black_protection.md)
* [Centrify](datasource_centrify_centrify.md)
* [Cimtrak](datasource_cimtrak_cimtrak.md)
* [Code42](datasource_code42_code42.md)
* [CrowdStrike Falcon](datasource_crowdstrike_falcon_crowdstrike_falcon.md)
* [CyberArk Vault](datasource_cyberark_vault_cyberark_vault.md)
* [Cylance PROTECT](datasource_cylance_protect_cylance_protect.md)
* [DatalakePortal](datasource_datalakeportal_datalakeportal.md)
* [Dell EMC](datasource_dell_emc_dell_emc.md)
* [Digital Guardian Endpoint Protection](datasource_digital_guardian_endpoint_protection_digital_guardian_endpoint_protection.md)
* [Dropbox](datasource_dropbox_dropbox.md)
* [Dtex](datasource_dtex_dtex.md)
* [Egnyte](datasource_egnyte_egnyte.md)
* [ExamWorkspace](datasource_examworkspace_examworkspace.md)
* [FTP](datasource_ftp_ftp.md)
* [FileAuditor](datasource_fileauditor_fileauditor.md)
* [Google](datasource_google_drive_google.md)
* [IBM DB2](datasource_ibm_db2_ibm_db2.md)
* [IPswitch](datasource_ipswitch_moveit_dmz_ipswitch.md)
* [IPswitch MoveIt](datasource_ipswitch_moveit_ipswitch_moveit.md)
* [Imperva File Activity Monitoring (FAM)](datasource_imperva_file_activity_monitoring_(fam)_imperva_file_activity_monitoring_(fam).md)
* [Kaspersky AV](datasource_kaspersky_av_kaspersky_av.md)
* [KiteWorks](datasource_kiteworks_kiteworks.md)
* [LOGBinder](datasource_logbinder_logbinder.md)
* [LanScope](datasource_lanscope_lanscope.md)
* [McAfee Endpoint Security](datasource_mcafee_endpoint_security_mcafee_endpoint_security.md)
* [Microsoft](datasource_microsoft_advanced_threat_protection_microsoft.md)
* [Microsoft CAS](datasource_microsoft_cas_microsoft_cas.md)
* [Sailpoint SIQ](datasource_microsoft_sharepoint_onpremise_sailpoint_siq.md)
* [Sailpoint SIQ](datasource_microsoft_sharepoint_online_sailpoint_siq.md)
* [Nasuni](datasource_nasuni_nasuni.md)
* [NetApp](datasource_netapp_netapp.md)
* [Sailpoint SIQ](datasource_netapp_sailpoint_siq.md)
* [NetDocs](datasource_netdocs_netdocs.md)
* [NetWrix](datasource_netwrix_netwrix.md)
* [Netskope Active Platform](datasource_netskope_active_platform_netskope_active_platform.md)
* [Microsoft Office 365](datasource_office_365_microsoft_office_365.md)
* [Sailpoint SIQ](datasource_onedrive_sailpoint_siq.md)
* [Palo Alto Networks Aperture](datasource_palo_alto_networks_aperture_palo_alto_networks_aperture.md)
* [Palo Alto Networks NGFW](datasource_palo_alto_networks_ngfw_palo_alto_networks_ngfw.md)
* [Quest Software](datasource_quest_software_change_auditor_quest_software.md)
* [RangerAudit](datasource_rangeraudit_rangeraudit.md)
* [SFTP](datasource_sftp_sftp.md)
* [SentinelOne](datasource_sentinelone_sentinelone.md)
* [ServiceNow](datasource_servicenow_servicenow.md)
* [SkySea ClientView](datasource_skysea_clientview_skysea_clientview.md)
* [Sophos Endpoint Protection](datasource_sophos_endpoint_protection_sophos_endpoint_protection.md)
* [StealthBits](datasource_stealthbits_stealthbits.md)
* [Symantec](datasource_symantec_cloudsoc_symantec.md)
* [Microsoft Sysmon](datasource_sysmon_microsoft_sysmon.md)
* [TrapX](datasource_tsoc_trapx.md)
* [TitanFTP](datasource_titanftp_titanftp.md)
* [Tripwire Enterprise](datasource_tripwire_enterprise_tripwire_enterprise.md)
* [Fox BoKS ServerControl](datasource_unix_fox_boks_servercontrol.md)
* [Unix](datasource_unix_unix.md)
* [Varonis Data Security Platform](datasource_varonis_data_security_platform_varonis_data_security_platform.md)
* [Vormetric](datasource_vormetric_vormetric.md)
* [Microsoft Windows](datasource_windows_microsoft_windows.md)
* [Sailpoint SIQ](datasource_windows_sailpoint_siq.md)


### Exabeam Event Types

- 
- file-alert
- file-delete
- file-permission-change
- file-read
- file-write
- sequence-end
### Exabeam Content Library for this Use Case


_Rules_
- A-FA-LSASS : Possible Mimikatz attack on this asset by a user process
- FA-EXT : A file has been written and is suspected of Ransomware on host
- FA-FG-A : Abnormal access to folder for group
- FA-FG-F : First access to folder for group
- FA-FT-EXEC : Non-Executive user accessed executive folder
- FA-FT-PRIV : Non-Privileged user accessed privileged folder
- FA-FU-A : Abnormal access to folder by user
- FA-FU-F : First access to folder by user
- FA-GD-A : Abnormal file server access for group
- FA-GD-F : First file server access for group
- FA-LSASS : Possible Mimikatz attack by a user process
- FA-OG-A : Abnormal access to source code files for user in the peer group
- FA-OG-F : First access to source code files for user in the peer group
- FA-OU-A : Abnormal access to source code files for user in the organization
- FA-OU-F : First access to source code files for user in the organization
- FA-OZ-A : Abnormal file access from network zone for organization
- FA-OZ-F : First file access from network zone for organization
- FA-SFU-A : Abnormal access to folder containing source code by user
- FA-SFU-F : First access to folder containing source code by user
- FA-TEMP-DIRECTORY-A : Abnormal process has been executed from a temporary directory by this user during file activity
- FA-TEMP-DIRECTORY-F : First time process has been executed from a temporary directory by this user during file activity
- FA-UA-A : Abnormal file access activity for user
- FA-UA-F : First file access activity for user
- FA-UD-A : Abnormal file server access for user
- FA-UD-F : First file server access for user
- FA-UFCOUNT : Abnormal number of files accessed
- FA-UFCOUNT-DELETE : Abnormal number of deleted files in a day
- FA-UH-A : Abnormal file access from asset for user
- FA-UH-DELETE : Abnormal number of hosts where files were deleted from
- FA-UH-F : First file access from asset for user
- FA-UR-A : Abnormal number of file accesses from repository by privileged user
- FA-URCOUNT-A : Abnormal number of file reads
- FA-UWCOUNT-A : Abnormal number of file writes
- FA-UZ-A : Abnormal file access from network zone for user


_Exabeam Models_
- FA-FG : 
- FA-FT-EXEC : 
- FA-FT-PRIV : 
- FA-FU : 
- FA-GD : 
- FA-OG : 
- FA-OU : 
- FA-OZ : 
- FA-SFU : 
- FA-UA : 
- FA-UD : 
- FA-UFCOUNT : 
- FA-UFCOUNT-DELETE : 
- FA-UH : 
- FA-UH-DELETE : 
- FA-UP-TEMP : 
- FA-UR : 
- FA-URCOUNT : 
- FA-UWCOUNT : 
- FA-UZ : 
- FACT : 
