Use Case: Badge Access
======================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [AMAG](datasource_badge_amag.md)
* [CCURE](datasource_badge_ccure.md)
* [DataWatch](datasource_badge_datawatch.md)
* [Galaxy](datasource_badge_galaxy.md)
* [Gallagher](datasource_badge_gallagher.md)
* [Honeywell](datasource_badge_honeywell.md)
* [Honeywell WIN-PAK](datasource_badge_honeywell_win-pak.md)
* [ICPAM](datasource_badge_icpam.md)
* [Lenel](datasource_badge_lenel.md)
* [ProWatch](datasource_badge_prowatch.md)
* [RS2 Technologies](datasource_badge_rs2_technologies.md)
* [RedCloud](datasource_badge_redcloud.md)
* [Siemens](datasource_badge_siemens.md)
* [Swipes](datasource_badge_swipes.md)
* [TimeLox](datasource_badge_timelox.md)
* [Unknown](datasource_badge_unknown.md)
* [Vanderbilt](datasource_badge_vanderbilt.md)
* [Viscount](datasource_badge_viscount.md)
* [Badgepoint](datasource_badgepoint_badgepoint.md)
* [Brivo](datasource_brivo_brivo.md)
* [KABA EXOS](datasource_exos_kaba_exos.md)
* [Genetec](datasource_genetec_genetec.md)
* [Lyrix](datasource_lyrix_lyrix.md)
* [Visma](datasource_megaflex_visma.md)
* [Paxton](datasource_net2door_paxton.md)
* [Onguard](datasource_onguard_onguard.md)
* [PicturePerfect](datasource_pictureperfect_pictureperfect.md)
* [RS2](datasource_rs2_rs2.md)
* [SecurityExpert](datasource_securityexpert_securityexpert.md)
* [Sensormatik](datasource_sensormatik_sensormatik.md)
* [Siemens](datasource_siemens_siemens.md)


### Exabeam Event Types

- 
- failed-physical-access
- physical-access
- session-end
### Exabeam Content Library for this Use Case


_Rules_
- FPA-DU : Failed badge access by disabled user
- FPA-UB-F : Failed physical access in new building for user
- FPA-UC-F : Failed physical access in new location for user
- FPA-UD-F : Failed physical access to new door for user
- PA-BU : INTERNAL: Building is not new OR it has converged
- PA-COUNT : Abnormal number of badge accesses
- PA-CU : INTERNAL: Location is not new OR it has converged
- PA-DU : Badge access by disabled user
- PA-MC : Badge access in multiple cities within a session
- PA-UB-A : Abnormal physical access in this building for user
- PA-UB-F : First physical access in this building for user
- PA-UC-A : Abnormal physical access in this location for user
- PA-UC-F : First physical access in this location for user
- PA-UD-F : First physical access to door for user
- PA-WU : Badge access by watchlist user


_Exabeam Models_
- FACT : 
- PA-BU : 
- PA-COUNT : 
- PA-CU : 
- PA-UB : 
- PA-UC : 
- PA-UD : 
