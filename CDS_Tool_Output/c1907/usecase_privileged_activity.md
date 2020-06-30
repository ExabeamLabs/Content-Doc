Use Case: Privileged Activity
=============================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [AD Audit](datasource_ad_audit_ad_audit.md)
* [BeyondTrust PasswordSafe](datasource_beyondtrust_passwordsafe_beyondtrust_passwordsafe.md)
* [BeyondTrust PowerBroker](datasource_beyondtrust_powerbroker_beyondtrust_powerbroker.md)
* [Microsoft Windows](datasource_dc_microsoft_windows.md)
* [Lieberman](datasource_enterprise_random_password_manager_lieberman.md)
* [Namespace rDirectory](datasource_namespace_rdirectory_namespace_rdirectory.md)
* [Quest Software](datasource_quest_software_change_auditor_quest_software.md)
* [StealthBits](datasource_stealthbits_stealthbits.md)
* [Trend Micro OfficeScan](datasource_trend_micro_officescan_trend_micro_officescan.md)
* [VMware](datasource_vmware_vmware.md)
* [Microsoft Windows](datasource_windows_microsoft_windows.md)


### Exabeam Event Types

- 
- audit-log-clear
- audit-policy-change
- ds-access
- failed-ds-access
- privileged-access
- privileged-object-access
### Exabeam Content Library for this Use Case


_Rules_
- A-WA-F : Audit log has been cleared on this asset
- AE-UA-FA : First audit activity type for user
- DS-APRIV : Non-Privileged user accessing privileged directory service attribute
- DS-GH-A : Abnormal directory service activity on host for peer group
- DS-GH-F : First directory service activity on host for peer group
- DS-GOC-A : Abnormal directory service object class for peer group
- DS-GOC-F : First directory service object class for peer group
- DS-GSZ-A : Abnormal directory service activity from source zone for peer group
- DS-GSZ-F : First directory service activity from source zone for peer group
- DS-OA : Internal: Privileged user accessing privileged directory service attribute in the organization
- DS-OAT-A : Abnormal directory service activity type for object class
- DS-OAT-F : First directory service activity type for object class
- DS-OG-F : First directory service event for user in the peer group
- DS-OH-A : Abnormal directory service activity on host for organization
- DS-OH-F : First directory service activity on host for organization
- DS-OOC-A : Abnormal directory service object class for organization
- DS-OOC-F : First directory service object class for organization
- DS-OSZ-A : Abnormal directory service activity from source zone for organization
- DS-OSZ-F : First directory service activity from source zone for organization
- DS-OU-F : First directory service event for user in the organization
- DS-UA : First access to attribute for privileged user
- DS-UAT-A : Abnormal directory service activity type for user per object class
- DS-UAT-F : First directory service activity type for user per object class
- DS-UH-A : Abnormal directory service activity on host for user
- DS-UH-F : First directory service activity on host for user
- DS-UOC-A : Abnormal directory service object class for user
- DS-UOC-F : First directory service object class for user
- DS-USH-A : Abnormal directory service activity on source host for user
- DS-USH-F : First directory service activity on source host for user
- DS-USZ-A : Abnormal directory service activity from source zone for user
- DS-USZ-F : First directory service activity from source zone for user
- FDS-OG : Failed directory service event for user in the peer group
- FDS-OG-F : First directory service event for user and it failed in the peer group
- FDS-OU : Failed directory service event for user in the organization
- FDS-OU-F : First directory service event for user and it failed in the organization
- WPA-GP-A : Abnormal privileged process for peer group
- WPA-GP-F : First privileged process for peer group
- WPA-HP-A : Abnormal privileged process for host
- WPA-HP-F : First privileged process for host
- WPA-HU : INTERNAL: Abnormal or first privileged access for user on asset
- WPA-HZ-F : First privileged access event on host from zone
- WPA-OG-F : First privileged access event for user for peer group
- WPA-OH-F : First execution of critical windows command using privileged access on this host in the organization
- WPA-OP-A : Abnormal privileged process for organization
- WPA-OP-F : First privileged process for organization
- WPA-OU-F : First privileged access event for user for organization
- WPA-PD-A : Abnormal directory for privileged process
- WPA-PD-F : First directory for privileged process
- WPA-UH-F : First privileged access event on host for user
- WPA-UP-A : Abnormal privileged process for user
- WPA-UP-F : First privileged process for user
- WPA-USH-F : First privileged access event on source host for user


_Exabeam Models_
- AE-UA : 
- DS-APRIV : 
- DS-GH : 
- DS-GOC : 
- DS-GSZ : 
- DS-OA : 
- DS-OAT : 
- DS-OG : 
- DS-OH : 
- DS-OOC : 
- DS-OSZ : 
- DS-OU : 
- DS-UA : 
- DS-UAT : 
- DS-UH : 
- DS-UOC : 
- DS-USH : 
- DS-USZ : 
- FACT : 
- WPA-GP : Privileged processes for peer group
- WPA-GP-All : 
- WPA-HP : Processes for host
- WPA-HU : 
- WPA-HZ : 
- WPA-OG : 
- WPA-OH : 
- WPA-OP : Processes for organization
- WPA-OU : 
- WPA-PD : 
- WPA-UH : 
- WPA-UP : Privileged processes for user
- WPA-UP-All : 
- WPA-USH : 
