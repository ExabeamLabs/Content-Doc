Use Case: Asset Activity Monitoring
===================================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [CrowdStrike Falcon](datasource_crowdstrike_falcon_crowdstrike_falcon.md)
* [Microsoft Windows](datasource_windows_microsoft_windows.md)


### Exabeam Event Types

- service-created
- task-created
### Exabeam Content Library for this Use Case


_Rules_
- WSC-GH-F : First service installation on host in the peer group
- WSC-GS-A : Unusual service name in the peer group
- WSC-HT-TOW-A : Service created at an unusual time for this host
- WSC-OH-F : First service installation on host in the organization
- WSC-OS-A : Unusual service name in the organization
- WSC-SP-A : Unusual process for service
- WSC-SP-POWERSHELL : Service created to execute sensitive process
- WSC-UH-F : First service installation on host by the user
- WSC-US-A : Unusual service name in the user
- WTC-GH-F : First scheduled task on host in the peer group
- WTC-GT-A : Unusual task name in the peer group
- WTC-HT-EXEC : Non-Executive user created a scheduled task/service on executive asset
- WTC-HT-PRIV : Non-Privileged user created a scheduled task/service on privileged asset
- WTC-HT-TOW-A : Scheduled task created at an unusual time for this host
- WTC-OH-F : First scheduled task on host in the organization
- WTC-OT-A : Unusual task name in the organization
- WTC-TP-A : Unusual process for scheduled task
- WTC-TP-POWERSHELL : Scheduled task created to execute sensitive process
- WTC-UH-F : First scheduled task on host for the user
- WTC-UT-A : Unusual task name in the user


_Exabeam Models_
- AL-HT-EXEC : 
- AL-HT-PRIV : 
- FACT : 
- WSC-GH : 
- WSC-GS : 
- WSC-OH : 
- WSC-OS : 
- WSC-SP : 
- WSC-UH : 
- WSC-US : 
- WTC-GH : 
- WTC-GT : 
- WTC-OH : Hosts on which scheduled tasks are created in the organization
- WTC-OT : 
- WTC-TP : 
- WTC-UH : 
- WTC-UT : 
- WTS-HT-TOW : 
