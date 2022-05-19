 Security Content c2109.2 Release Notes
=======================================

These Release Notes document security content updates from content package c2108.2 to c2109.2.

The security content updates listed below include changes to the following areas:

* [Parsers](#Parsers)

* [Models](#Models)

* [Rules](#Rules)

In the lists below, each item represents a specific parser, model, or rule that has been added, updated, or deprecated. To facilitate finding every data source where the changed content items are referenced, a content library query has been created for each changed parser, model, or rule. To view the results of each query, click on the link for the relevant content item.

Parsers
-------

* [New](#New-Parsers)

* [Updated](#Updated-Parsers)

* [Deprecated](#Deprecated-Parsers)

#### New Parsers
* [ad-audit-4743](https://github.com/ExabeamLabs/Content-Doc/search?q=ad-audit-4743)

* [azure-ad-account-password-change-2](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-ad-account-password-change-2)

* [azure-ad-account-password-change-3](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-ad-account-password-change-3)

* [azure-ad-member-added-1](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-ad-member-added-1)

* [azure-mfa-auth-failed-2](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-mfa-auth-failed-2)

* [bitglass-failed-login](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-failed-login)

* [bitglass-file-download-1](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-file-download-1)

* [bitglass-file-download](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-file-download)

* [cassandra-db-activity-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=cassandra-db-activity-failed)

* [cassandra-db-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cassandra-db-login)

* [cassandra-db-update](https://github.com/ExabeamLabs/Content-Doc/search?q=cassandra-db-update)

* [cef-carbonblack-edr-process-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-edr-process-alert)

* [cef-cisco-dns-response-sk4-ad-computers](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-ad-computers)

* [cef-cisco-dns-response-sk4-ad-users](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-ad-users)

* [cef-cisco-dns-response-sk4-internal-networks](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-internal-networks)

* [cef-cisco-dns-response-sk4-networks](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-networks)

* [cef-cisco-dns-response-sk4-roaming-client](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-roaming-client)

* [cef-cisco-dns-response-sk4-roaming-computer](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-roaming-computer)

* [cef-dropbox-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-dropbox-app-activity-10)

* [cef-dropbox-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-dropbox-app-activity-9)

* [cef-dropbox-login-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-dropbox-login-activity)

* [cef-netapp-file-operations-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netapp-file-operations-1)

* [cef-ping-auth-successful-6](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-successful-6)

* [cef-ping-auth-successful-7](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-successful-7)

* [cef-symantec-atp-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-symantec-atp-alert-1)

* [cef-symantec-sep-alert-5](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-symantec-sep-alert-5)

* [checkpoint-network-connection-accept-1](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-network-connection-accept-1)

* [checkpoint-network-connection-drop-1](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-network-connection-drop-1)

* [fortinet-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=fortinet-web-activity-2)

* [gcp-ids-network-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=gcp-ids-network-alert)

* [iboss-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=iboss-web-activity)

* [ironport-proxy-parser-15](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-15)

* [ironport-proxy-parser-16](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-16)

* [json-cisco-netflow-connection-1](https://github.com/ExabeamLabs/Content-Doc/search?q=json-cisco-netflow-connection-1)

* [json-eyeinspect-failed-logon](https://github.com/ExabeamLabs/Content-Doc/search?q=json-eyeinspect-failed-logon)

* [json-irondefense-network-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=json-irondefense-network-alert)

* [json-malwarebytes-web-activity-denied](https://github.com/ExabeamLabs/Content-Doc/search?q=json-malwarebytes-web-activity-denied)

* [json-zeek-network-connection-1](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek-network-connection-1)

* [json-zeek-network-connection-2](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek-network-connection-2)

* [json-zeek-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek-network-connection)

* [lastpass-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=lastpass-app-login-1)

* [lastpass-app-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=lastpass-app-login-failed)

* [openvms-batch-logon](https://github.com/ExabeamLabs/Content-Doc/search?q=openvms-batch-logon)

* [openvms-failed-logon](https://github.com/ExabeamLabs/Content-Doc/search?q=openvms-failed-logon)

* [openvms-file-access](https://github.com/ExabeamLabs/Content-Doc/search?q=openvms-file-access)

* [openvms-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=openvms-file-delete)

* [openvms-remote-login](https://github.com/ExabeamLabs/Content-Doc/search?q=openvms-remote-login)

* [oracle-database-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-database-delete)

* [raw-4743-1](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4743-1)

* [raw-4743](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4743)

* [raw-defender-av-1116](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-defender-av-1116)

* [s-dropbox-logins-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-dropbox-logins-activity)

* [s-mcafee-usb-insert-cddrive](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mcafee-usb-insert-cddrive)

* [s-mcafee-usb-insert-dd](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mcafee-usb-insert-dd)

* [s-mcafee-usb-insert-pd](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mcafee-usb-insert-pd)

* [s-mcafee-usb-insert-usbd](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mcafee-usb-insert-usbd)

* [s-snowflake-db-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-snowflake-db-login-1)

* [s-snowflake-db-query-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-snowflake-db-query-1)

* [seclore-file-permission-change-1](https://github.com/ExabeamLabs/Content-Doc/search?q=seclore-file-permission-change-1)

* [seclore-file-permission-change-2](https://github.com/ExabeamLabs/Content-Doc/search?q=seclore-file-permission-change-2)

* [seclore-file-permission-change](https://github.com/ExabeamLabs/Content-Doc/search?q=seclore-file-permission-change)

* [seclore-file-read-1](https://github.com/ExabeamLabs/Content-Doc/search?q=seclore-file-read-1)

* [seclore-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=seclore-file-read)

* [seclore-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=seclore-file-write)

* [securesphere-db-failed-login-3](https://github.com/ExabeamLabs/Content-Doc/search?q=securesphere-db-failed-login-3)

* [securesphere-db-login-2](https://github.com/ExabeamLabs/Content-Doc/search?q=securesphere-db-login-2)

* [skyformation-prisma-security-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=skyformation-prisma-security-alert-2)

* [symantec-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-web-activity-2)

* [symantec-web-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-web-activity-3)

* [tanium-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=tanium-file-delete)

* [tanium-file-owner-change](https://github.com/ExabeamLabs/Content-Doc/search?q=tanium-file-owner-change)

* [tanium-file-permission-change](https://github.com/ExabeamLabs/Content-Doc/search?q=tanium-file-permission-change)

* [tanium-file-rename](https://github.com/ExabeamLabs/Content-Doc/search?q=tanium-file-rename)

* [tanium-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=tanium-file-write)

* [tanium-new-file-create](https://github.com/ExabeamLabs/Content-Doc/search?q=tanium-new-file-create)

* [vontu-dlp-1](https://github.com/ExabeamLabs/Content-Doc/search?q=vontu-dlp-1)

* [windows-kinesis-firehose-5156](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-kinesis-firehose-5156)

* [xml-10014](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-10014)

* [xml-10015](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-10015)

* [xml-10024](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-10024)

* [xml-10025](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-10025)

* [xml-1149](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-1149)

* [xml-30009](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-30009)

* [xml-30010](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-30010)

* [xml-30028](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-30028)

* [xml-30029](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-30029)

* [xml-sysmon-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-sysmon-alert)

* [zscaler-vpn-end-1](https://github.com/ExabeamLabs/Content-Doc/search?q=zscaler-vpn-end-1)


#### Updated Parsers
* [O365-email-alert-in](https://github.com/ExabeamLabs/Content-Doc/search?q=O365-email-alert-in)

* [O365-email-alert-out](https://github.com/ExabeamLabs/Content-Doc/search?q=O365-email-alert-out)

* [accelion-kite-app-3](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-3)

* [accelion-kite-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-activity-2)

* [accelion-kite-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-activity-3)

* [accelion-kite-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-activity-4)

* [accelion-kite-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-activity-5)

* [accelion-kite-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-activity-6)

* [accelion-kite-app-activity-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-activity-email-alert)

* [accelion-kite-app-admin-login](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-admin-login)

* [accelion-kite-app-delete-draft](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-delete-draft)

* [accelion-kite-app-download-1](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-download-1)

* [accelion-kite-app-download](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-download)

* [accelion-kite-app-file-delete-1](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-file-delete-1)

* [accelion-kite-app-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-file-delete)

* [accelion-kite-app-file-withdraw](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-file-withdraw)

* [accelion-kite-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-login-1)

* [accelion-kite-app-network-setting](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-network-setting)

* [accelion-kite-app-password-change](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-password-change)

* [accelion-kite-app-reset-password](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-reset-password)

* [accelion-kite-app-setting](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-setting)

* [accelion-kite-app-system](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-system)

* [accelion-kite-app-user-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-app-user-delete)

* [accelion-kite-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=accelion-kite-failed-app-login)

* [ad-audit-4663-1](https://github.com/ExabeamLabs/Content-Doc/search?q=ad-audit-4663-1)

* [ad-audit-5139](https://github.com/ExabeamLabs/Content-Doc/search?q=ad-audit-5139)

* [ad-json-member-added-2008](https://github.com/ExabeamLabs/Content-Doc/search?q=ad-json-member-added-2008)

* [airlock-create-folder](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-create-folder)

* [airlock-disconnect](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-disconnect)

* [airlock-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-file-delete)

* [airlock-file-download-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-file-download-failed)

* [airlock-file-download](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-file-download)

* [airlock-file-upload-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-file-upload-failed)

* [airlock-file-upload](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-file-upload)

* [airlock-firewall-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-firewall-network-connection)

* [airlock-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-login-failed)

* [airlock-login-success](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-login-success)

* [airlock-logout](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-logout)

* [airlock-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-network-connection)

* [airlock-rename-folder](https://github.com/ExabeamLabs/Content-Doc/search?q=airlock-rename-folder)

* [akamai-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=akamai-web-activity)

* [asa-web-activity-716003](https://github.com/ExabeamLabs/Content-Doc/search?q=asa-web-activity-716003)

* [auditd-unix-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=auditd-unix-process-created)

* [auth0-login-failed-1](https://github.com/ExabeamLabs/Content-Doc/search?q=auth0-login-failed-1)

* [auth0-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=auth0-login-failed)

* [auth0-login-success](https://github.com/ExabeamLabs/Content-Doc/search?q=auth0-login-success)

* [auth0-password-breached](https://github.com/ExabeamLabs/Content-Doc/search?q=auth0-password-breached)

* [auth0-password-change-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=auth0-password-change-failed)

* [azure-ad-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-ad-app-login)

* [azure-app-auth-events](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-app-auth-events)

* [azure-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-app-login)

* [azure-app-logon-2](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-app-logon-2)

* [azure-atp-security-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-atp-security-alert-3)

* [azure-atp-security-alert-4](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-atp-security-alert-4)

* [azure-event-hub-application-gateway-access-log](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-application-gateway-access-log)

* [azure-event-hub-application-gateway-firewall-log](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-application-gateway-firewall-log)

* [azure-event-hub-file-events](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-file-events)

* [azure-event-hub-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-file-read)

* [azure-event-hub-key-vault-auth](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-key-vault-auth)

* [azure-event-hub-member-added](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-member-added)

* [azure-event-hub-member-removed](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-member-removed)

* [azure-event-hub-network-security-group-event](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-network-security-group-event)

* [azure-event-hub-network-security-group-rule-counter](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-network-security-group-rule-counter)

* [azure-event-hub-process-events-1](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-process-events-1)

* [azure-event-hub-process-events](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-process-events)

* [azure-event-hub-sql-security-event](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-sql-security-event)

* [azure-event-hub-usb-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-usb-activity)

* [azure-event-hub-usb-insert](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-event-hub-usb-insert)

* [azure-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-file-read)

* [azure-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-file-write)

* [azure-mfa-admin-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-mfa-admin-activity)

* [azure-security-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-security-alert-2)

* [azure-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-security-alert)

* [azure-security-center-network-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-security-center-network-alert)

* [azure-security-center-security-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-security-center-security-alert-3)

* [azure-security-center-security-alert-4](https://github.com/ExabeamLabs/Content-Doc/search?q=azure-security-center-security-alert-4)

* [barracuda-email](https://github.com/ExabeamLabs/Content-Doc/search?q=barracuda-email)

* [bind-dns-query-2](https://github.com/ExabeamLabs/Content-Doc/search?q=bind-dns-query-2)

* [bind-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=bind-dns-query)

* [bitglass-app-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-app-login-failed)

* [bitglass-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-app-login)

* [bitglass-dlp-email-alert-out](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-dlp-email-alert-out)

* [bitglass-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-file-read)

* [bitglass-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=bitglass-file-write)

* [bluecoat-proxy-10](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-10)

* [bluecoat-proxy-11](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-11)

* [bluecoat-proxy-12](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-12)

* [bluecoat-proxy-13](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-13)

* [bluecoat-proxy-14](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-14)

* [bluecoat-proxy-15](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-15)

* [bluecoat-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-1)

* [bluecoat-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-2)

* [bluecoat-proxy-3](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-3)

* [bluecoat-proxy-4](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-4)

* [bluecoat-proxy-5](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-5)

* [bluecoat-proxy-6](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-6)

* [bluecoat-proxy-7](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-7)

* [bluecoat-proxy-8](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-8)

* [bluecoat-proxy-9](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-9)

* [bluecoat-proxy-v2](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-v2)

* [bluecoat-proxy-v3](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-v3)

* [bluecoat-proxy-v4](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-v4)

* [bluecoat-proxy-v5](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-v5)

* [bluecoat-proxy-v6](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-v6)

* [bluecoat-proxy-v7](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-proxy-v7)

* [bluecoat-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=bluecoat-web-activity)

* [bro-httpeth0](https://github.com/ExabeamLabs/Content-Doc/search?q=bro-httpeth0)

* [bro-smtp](https://github.com/ExabeamLabs/Content-Doc/search?q=bro-smtp)

* [bro-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=bro-web-activity)

* [carbonblack-edr-crossproc](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-edr-crossproc)

* [carbonblack-edr-filemod](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-edr-filemod)

* [carbonblack-edr-netconn](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-edr-netconn)

* [carbonblack-edr-procstart-1](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-edr-procstart-1)

* [carbonblack-edr-procstart](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-edr-procstart)

* [carbonblack-endpoint-process-file](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-endpoint-process-file)

* [carbonblack-endpoint-process-network](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-endpoint-process-network)

* [carbonblack-endpoint-process-start](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-endpoint-process-start)

* [carbonblack-file-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-file-activity)

* [carbonblack-file-operations](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-file-operations)

* [carbonblack-process-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-process-alert)

* [carbonblack-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-process-created)

* [carbonblack-security-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-security-alert-2)

* [carbonblack-usb-insert](https://github.com/ExabeamLabs/Content-Doc/search?q=carbonblack-usb-insert)

* [cas-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cas-app-activity)

* [cas-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=cas-login-failed)

* [cas-login-success](https://github.com/ExabeamLabs/Content-Doc/search?q=cas-login-success)

* [cc-carbonblack-edr-crossproc](https://github.com/ExabeamLabs/Content-Doc/search?q=cc-carbonblack-edr-crossproc)

* [cc-carbonblack-edr-filemod](https://github.com/ExabeamLabs/Content-Doc/search?q=cc-carbonblack-edr-filemod)

* [cc-carbonblack-edr-netconn](https://github.com/ExabeamLabs/Content-Doc/search?q=cc-carbonblack-edr-netconn)

* [cc-carbonblack-edr-procstart](https://github.com/ExabeamLabs/Content-Doc/search?q=cc-carbonblack-edr-procstart)

* [cc-carbonblack-process-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cc-carbonblack-process-alert-1)

* [cds-process-creation](https://github.com/ExabeamLabs/Content-Doc/search?q=cds-process-creation)

* [cef-1102](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-1102)

* [cef-O365-dlp-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-O365-dlp-email-in)

* [cef-O365-dlp-email-out-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-O365-dlp-email-out-1)

* [cef-O365-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-O365-dlp-email-out)

* [cef-azure-ad-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-ad-app-login)

* [cef-azure-event-hub-security](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-event-hub-security)

* [cef-azure-onedrive-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-10)

* [cef-azure-onedrive-app-activity-11](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-11)

* [cef-azure-onedrive-app-activity-12](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-12)

* [cef-azure-onedrive-app-activity-13](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-13)

* [cef-azure-onedrive-app-activity-14](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-14)

* [cef-azure-onedrive-app-activity-15](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-15)

* [cef-azure-onedrive-app-activity-16](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-16)

* [cef-azure-onedrive-app-activity-17](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-17)

* [cef-azure-onedrive-app-activity-18](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-18)

* [cef-azure-onedrive-app-activity-19](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-19)

* [cef-azure-onedrive-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-1)

* [cef-azure-onedrive-app-activity-20](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-20)

* [cef-azure-onedrive-app-activity-21](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-21)

* [cef-azure-onedrive-app-activity-22](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-22)

* [cef-azure-onedrive-app-activity-23](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-23)

* [cef-azure-onedrive-app-activity-24](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-24)

* [cef-azure-onedrive-app-activity-25](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-25)

* [cef-azure-onedrive-app-activity-26](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-26)

* [cef-azure-onedrive-app-activity-27](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-27)

* [cef-azure-onedrive-app-activity-28](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-28)

* [cef-azure-onedrive-app-activity-29](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-29)

* [cef-azure-onedrive-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-2)

* [cef-azure-onedrive-app-activity-30](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-30)

* [cef-azure-onedrive-app-activity-31](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-31)

* [cef-azure-onedrive-app-activity-32](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-32)

* [cef-azure-onedrive-app-activity-33](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-33)

* [cef-azure-onedrive-app-activity-34](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-34)

* [cef-azure-onedrive-app-activity-35](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-35)

* [cef-azure-onedrive-app-activity-36](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-36)

* [cef-azure-onedrive-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-3)

* [cef-azure-onedrive-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-4)

* [cef-azure-onedrive-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-5)

* [cef-azure-onedrive-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-6)

* [cef-azure-onedrive-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-7)

* [cef-azure-onedrive-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-8)

* [cef-azure-onedrive-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-azure-onedrive-app-activity-9)

* [cef-bit9-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bit9-app-login)

* [cef-bit9-epp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bit9-epp-alert)

* [cef-bit9-file-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bit9-file-alert)

* [cef-bit9-process-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bit9-process-alert)

* [cef-bit9-usb-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bit9-usb-activity)

* [cef-bitdefender-gravityzone-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bitdefender-gravityzone-alert)

* [cef-bluecoat-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-bluecoat-proxy)

* [cef-carbonblack-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-alert-1)

* [cef-carbonblack-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-alert-2)

* [cef-carbonblack-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-alert)

* [cef-carbonblack-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-app-login)

* [cef-carbonblack-endpoint-process](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-endpoint-process)

* [cef-carbonblack-file-create](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-create)

* [cef-carbonblack-file-read-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-read-1)

* [cef-carbonblack-file-read-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-read-2)

* [cef-carbonblack-file-write-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-write-1)

* [cef-carbonblack-file-write-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-write-2)

* [cef-carbonblack-file-write-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-write-3)

* [cef-carbonblack-file-write-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-file-write-4)

* [cef-carbonblack-local-logon-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-local-logon-3)

* [cef-carbonblack-local-logon](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-local-logon)

* [cef-carbonblack-network-connection-failed-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-network-connection-failed-1)

* [cef-carbonblack-network-connection-successful-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-network-connection-successful-1)

* [cef-carbonblack-network-connection-successful-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-network-connection-successful-2)

* [cef-carbonblack-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-network-connection)

* [cef-carbonblack-process-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-alert-1)

* [cef-carbonblack-process-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-alert-2)

* [cef-carbonblack-process-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-alert-3)

* [cef-carbonblack-process-alert-query](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-alert-query)

* [cef-carbonblack-process-alert-storage](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-alert-storage)

* [cef-carbonblack-process-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-alert)

* [cef-carbonblack-process-created-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-created-1)

* [cef-carbonblack-process-created-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-created-2)

* [cef-carbonblack-process-created-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-created-3)

* [cef-carbonblack-process-created-failed-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-created-failed-1)

* [cef-carbonblack-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-process-created)

* [cef-carbonblack-security-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-security-alert-1)

* [cef-carbonblack-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-security-alert)

* [cef-carbonblack-usb-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-usb-activity)

* [cef-carbonblack-workstation-locked-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-workstation-locked-2)

* [cef-carbonblack-workstation-locked](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-workstation-locked)

* [cef-carbonblack-workstation-unlocked-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-workstation-unlocked-2)

* [cef-carbonblack-workstation-unlocked](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-carbonblack-workstation-unlocked)

* [cef-cas-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cas-security-alert)

* [cef-catonetworks-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-catonetworks-web-activity)

* [cef-cisco-dns-response-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-1)

* [cef-cisco-dns-response-sk4-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-2)

* [cef-cisco-dns-response-sk4-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-3)

* [cef-cisco-dns-response-sk4-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4-4)

* [cef-cisco-dns-response-sk4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response-sk4)

* [cef-cisco-dns-response](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-dns-response)

* [cef-cisco-firepower-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cisco-firepower-dns-query)

* [cef-cloudflare-net-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cloudflare-net-connection)

* [cef-cortex-xdr-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-cortex-xdr-alert-1)

* [cef-defender-atp-network-con](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-defender-atp-network-con)

* [cef-digitalguardian-send-mail](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-digitalguardian-send-mail)

* [cef-dlp-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-dlp-email-in)

* [cef-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-dlp-email-out)

* [cef-dtex-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-dtex-web-activity)

* [cef-duo-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-duo-app-activity)

* [cef-duo-auth](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-duo-auth)

* [cef-duo-authentication](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-duo-authentication)

* [cef-f5-asm-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-f5-asm-alert)

* [cef-forcepoint-dlp-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-forcepoint-dlp-alert-1)

* [cef-forcepoint-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-forcepoint-dlp-alert)

* [cef-forcepoint-dlp-email-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-forcepoint-dlp-email-alert-1)

* [cef-forcepoint-dlp-email-alert-out](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-forcepoint-dlp-email-alert-out)

* [cef-forcepoint-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-forcepoint-dlp-email-alert)

* [cef-forcepoint-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-forcepoint-proxy)

* [cef-fortinet-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-fortinet-web-activity-1)

* [cef-fortinet-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-fortinet-web-activity)

* [cef-iis-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-iis-web-activity)

* [cef-incapsula-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-incapsula-web-activity-2)

* [cef-incapsula-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-incapsula-web-activity)

* [cef-infowatch-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-infowatch-email-alert)

* [cef-infowatch-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-infowatch-web-activity-1)

* [cef-infowatch-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-infowatch-web-activity)

* [cef-juniper-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-juniper-proxy)

* [cef-kaspersky-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-kaspersky-dlp-email)

* [cef-mcafee-dlp-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dlp-alert-2)

* [cef-mcafee-dlp-email-alert-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dlp-email-alert-failed)

* [cef-mcafee-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dlp-email-alert)

* [cef-mcafee-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dlp-email-out)

* [cef-mcafee-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dlp-email)

* [cef-mcafee-dlp-prevent](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dlp-prevent)

* [cef-mcafee-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mcafee-dns-query)

* [cef-microsoft-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-10)

* [cef-microsoft-app-activity-11](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-11)

* [cef-microsoft-app-activity-12](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-12)

* [cef-microsoft-app-activity-13](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-13)

* [cef-microsoft-app-activity-17](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-17)

* [cef-microsoft-app-activity-18](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-18)

* [cef-microsoft-app-activity-19](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-19)

* [cef-microsoft-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-1)

* [cef-microsoft-app-activity-20](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-20)

* [cef-microsoft-app-activity-21](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-21)

* [cef-microsoft-app-activity-22](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-22)

* [cef-microsoft-app-activity-23](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-23)

* [cef-microsoft-app-activity-24](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-24)

* [cef-microsoft-app-activity-25](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-25)

* [cef-microsoft-app-activity-26](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-26)

* [cef-microsoft-app-activity-27](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-27)

* [cef-microsoft-app-activity-28](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-28)

* [cef-microsoft-app-activity-29](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-29)

* [cef-microsoft-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-2)

* [cef-microsoft-app-activity-30](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-30)

* [cef-microsoft-app-activity-31](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-31)

* [cef-microsoft-app-activity-32](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-32)

* [cef-microsoft-app-activity-33](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-33)

* [cef-microsoft-app-activity-34](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-34)

* [cef-microsoft-app-activity-35](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-35)

* [cef-microsoft-app-activity-36](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-36)

* [cef-microsoft-app-activity-37](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-37)

* [cef-microsoft-app-activity-39](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-39)

* [cef-microsoft-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-3)

* [cef-microsoft-app-activity-40](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-40)

* [cef-microsoft-app-activity-41](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-41)

* [cef-microsoft-app-activity-42](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-42)

* [cef-microsoft-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-4)

* [cef-microsoft-app-activity-51](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-51)

* [cef-microsoft-app-activity-52](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-52)

* [cef-microsoft-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-5)

* [cef-microsoft-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-6)

* [cef-microsoft-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-7)

* [cef-microsoft-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-8)

* [cef-microsoft-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-9)

* [cef-microsoft-app-activity-inbox-rule](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-activity-inbox-rule)

* [cef-microsoft-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-app-login)

* [cef-microsoft-database-failed-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-database-failed-login-1)

* [cef-microsoft-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-microsoft-failed-app-login)

* [cef-mimecast-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-dlp-email)

* [cef-mimecast-email-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-email-alert-1)

* [cef-mimecast-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-email-alert)

* [cef-mimecast-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-failed-app-login)

* [cef-mimecast-message-view](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-message-view)

* [cef-mimecast-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-security-alert)

* [cef-mimecast-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mimecast-web-activity)

* [cef-moveit-app-failed-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-moveit-app-failed-login)

* [cef-moveit-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-moveit-app-login)

* [cef-mwg-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-mwg-proxy)

* [cef-netskope-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert-1)

* [cef-netskope-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert-2)

* [cef-netskope-alert-anomaly](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert-anomaly)

* [cef-netskope-alert-compromise](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert-compromise)

* [cef-netskope-alert-malsite](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert-malsite)

* [cef-netskope-alert-policy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert-policy)

* [cef-netskope-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-alert)

* [cef-netskope-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-10)

* [cef-netskope-app-activity-11](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-11)

* [cef-netskope-app-activity-12](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-12)

* [cef-netskope-app-activity-13](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-13)

* [cef-netskope-app-activity-14](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-14)

* [cef-netskope-app-activity-15](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-15)

* [cef-netskope-app-activity-16](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-16)

* [cef-netskope-app-activity-17](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-17)

* [cef-netskope-app-activity-18](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-18)

* [cef-netskope-app-activity-19](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-19)

* [cef-netskope-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-1)

* [cef-netskope-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-2)

* [cef-netskope-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-3)

* [cef-netskope-app-activity-45](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-45)

* [cef-netskope-app-activity-46](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-46)

* [cef-netskope-app-activity-47](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-47)

* [cef-netskope-app-activity-48](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-48)

* [cef-netskope-app-activity-49](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-49)

* [cef-netskope-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-4)

* [cef-netskope-app-activity-50](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-50)

* [cef-netskope-app-activity-51](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-51)

* [cef-netskope-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-5)

* [cef-netskope-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-6)

* [cef-netskope-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-7)

* [cef-netskope-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-8)

* [cef-netskope-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-activity-9)

* [cef-netskope-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-login-1)

* [cef-netskope-app-login-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-app-login-2)

* [cef-netskope-dlp-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-dlp-alert-1)

* [cef-netskope-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-dlp-alert)

* [cef-netskope-dlp-email-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-dlp-email-alert-1)

* [cef-netskope-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-failed-app-login)

* [cef-netskope-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-web-activity-1)

* [cef-netskope-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-web-activity)

* [cef-netskope-web-policy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-web-policy-1)

* [cef-netskope-web-policy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-netskope-web-policy)

* [cef-o365-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-10)

* [cef-o365-app-activity-11](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-11)

* [cef-o365-app-activity-12](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-12)

* [cef-o365-app-activity-13](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-13)

* [cef-o365-app-activity-14](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-14)

* [cef-o365-app-activity-15](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-15)

* [cef-o365-app-activity-16](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-16)

* [cef-o365-app-activity-17](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-17)

* [cef-o365-app-activity-18](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-18)

* [cef-o365-app-activity-19](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-19)

* [cef-o365-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-1)

* [cef-o365-app-activity-20](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-20)

* [cef-o365-app-activity-21](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-21)

* [cef-o365-app-activity-22](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-22)

* [cef-o365-app-activity-23](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-23)

* [cef-o365-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-2)

* [cef-o365-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-3)

* [cef-o365-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-4)

* [cef-o365-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-5)

* [cef-o365-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-6)

* [cef-o365-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-7)

* [cef-o365-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-8)

* [cef-o365-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-activity-9)

* [cef-o365-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-app-login-1)

* [cef-o365-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-dlp-email)

* [cef-o365-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-o365-security-alert)

* [cef-observeit-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-observeit-app-activity)

* [cef-okta-account-password-reset](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-okta-account-password-reset)

* [cef-okta-account-unlocked](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-okta-account-unlocked)

* [cef-okta-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-okta-app-activity)

* [cef-okta-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-okta-app-login)

* [cef-okta-logs-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-okta-logs-app-activity)

* [cef-okta-logs-app-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-okta-logs-app-alert)

* [cef-oracle-db-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-oracle-db-delete)

* [cef-oracle-db-query](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-oracle-db-query)

* [cef-oracle-db-update](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-oracle-db-update)

* [cef-pan-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-pan-proxy)

* [cef-ping-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-app-login-1)

* [cef-ping-auth-failed-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-failed-1)

* [cef-ping-auth-failed-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-failed-2)

* [cef-ping-auth-failed-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-failed-3)

* [cef-ping-auth-successful-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-successful-1)

* [cef-ping-auth-successful-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-successful-2)

* [cef-ping-auth-successful-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-successful-3)

* [cef-ping-auth-successful](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-auth-successful)

* [cef-ping-failed-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-ping-failed-app-login-1)

* [cef-proofpoint-dlp-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-dlp-alert-2)

* [cef-proofpoint-dlp-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-dlp-alert-3)

* [cef-proofpoint-email-in-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-email-in-1)

* [cef-proofpoint-email-in-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-email-in-failed)

* [cef-proofpoint-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-email-in)

* [cef-proofpoint-email-out-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-email-out-failed)

* [cef-proofpoint-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-proofpoint-email-out)

* [cef-salesforce-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-salesforce-app-login)

* [cef-securesphere-db-query-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-securesphere-db-query-1)

* [cef-security-graph-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-security-graph-alert)

* [cef-sentinelone-network-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-sentinelone-network-alert)

* [cef-sentinelone-security-alert-5](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-sentinelone-security-alert-5)

* [cef-sentinelone-security-alert-6](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-sentinelone-security-alert-6)

* [cef-servicenow-file-operation-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-servicenow-file-operation-2)

* [cef-servicenow-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-servicenow-login-1)

* [cef-servicenow-login-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-servicenow-login-2)

* [cef-servicenow-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-servicenow-login-failed)

* [cef-skyformation-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-skyformation-login)

* [cef-skyformation-mimecast-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-skyformation-mimecast-login)

* [cef-sophos-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-sophos-web-activity)

* [cef-symantec-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-symantec-email-alert)

* [cef-symantec-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-symantec-web-activity-1)

* [cef-symantec-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-symantec-web-activity-2)

* [cef-symantec-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-symantec-web-activity)

* [cef-syslog-oracle-db-login](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-syslog-oracle-db-login)

* [cef-syslog-oracle-db-query](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-syslog-oracle-db-query)

* [cef-trendmicro-dlp-email-alert-in](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-trendmicro-dlp-email-alert-in)

* [cef-trendmicro-dlp](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-trendmicro-dlp)

* [cef-unix-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-unix-dlp-email-alert)

* [cef-vectra-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-vectra-alert)

* [cef-vontu-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-vontu-dlp-alert)

* [cef-websense-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-websense-proxy)

* [cef-zscaler-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cef-zscaler-web-activity)

* [centrify-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=centrify-app-activity)

* [chcom-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=chcom-web-activity)

* [checkpoint-dlp-alert-out](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-dlp-alert-out)

* [checkpoint-firewall-allow-2](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-firewall-allow-2)

* [checkpoint-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-proxy-1)

* [checkpoint-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-proxy-2)

* [checkpoint-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-proxy)

* [checkpoint-url-filtering](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-url-filtering)

* [checkpoint-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-web-activity-1)

* [checkpoint-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=checkpoint-web-activity)

* [cisco-adc-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-adc-web-activity)

* [cisco-asa-746016](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-asa-746016)

* [cisco-asa-authentication-successful](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-asa-authentication-successful)

* [cisco-asa-connection-built-302013](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-asa-connection-built-302013)

* [cisco-asa-connection-teardown](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-asa-connection-teardown)

* [cisco-asa-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-asa-process-created)

* [cisco-dns-response-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-dns-response-1)

* [cisco-dns-response](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-dns-response)

* [cisco-esa-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-esa-dlp-alert)

* [cisco-ftd-746016](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-ftd-746016)

* [cisco-meraki-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-meraki-web-activity)

* [cisco-umbrella-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-umbrella-proxy)

* [cisco-w3c-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-w3c-proxy)

* [cisco-wsa-squid-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-wsa-squid-proxy)

* [cisco-wsa-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=cisco-wsa-web-activity)

* [citrix-endpoint-mgmt-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=citrix-endpoint-mgmt-activity)

* [cl-cisco-dns-response-sk4-4](https://github.com/ExabeamLabs/Content-Doc/search?q=cl-cisco-dns-response-sk4-4)

* [clearswift-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=clearswift-dlp-email)

* [code42-email-out-operations](https://github.com/ExabeamLabs/Content-Doc/search?q=code42-email-out-operations)

* [confer-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=confer-alert)

* [corelight-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=corelight-dns-query)

* [crowdstrike-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-app-activity-1)

* [crowdstrike-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-app-activity-2)

* [crowdstrike-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-app-activity-3)

* [crowdstrike-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-app-activity-4)

* [crowdstrike-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-app-activity)

* [crowdstrike-auth-failed-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-auth-failed-1)

* [crowdstrike-auth-failed-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-auth-failed-2)

* [crowdstrike-config-change](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-config-change)

* [crowdstrike-file-delete-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-delete-1)

* [crowdstrike-file-download-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-download-1)

* [crowdstrike-file-download](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-download)

* [crowdstrike-file-operations-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-operations-1)

* [crowdstrike-file-process-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-process-alert-2)

* [crowdstrike-file-read-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-read-2)

* [crowdstrike-file-read-3](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-read-3)

* [crowdstrike-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-read)

* [crowdstrike-file-write-10](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-10)

* [crowdstrike-file-write-11](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-11)

* [crowdstrike-file-write-12](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-12)

* [crowdstrike-file-write-13](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-13)

* [crowdstrike-file-write-14](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-14)

* [crowdstrike-file-write-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-1)

* [crowdstrike-file-write-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-2)

* [crowdstrike-file-write-3](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-3)

* [crowdstrike-file-write-4](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-4)

* [crowdstrike-file-write-5](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-5)

* [crowdstrike-file-write-6](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-6)

* [crowdstrike-file-write-7](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-7)

* [crowdstrike-file-write-8](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-8)

* [crowdstrike-file-write-9](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write-9)

* [crowdstrike-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-file-write)

* [crowdstrike-host-info](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-host-info)

* [crowdstrike-logon-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-logon-2)

* [crowdstrike-logon](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-logon)

* [crowdstrike-modify-binary](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-modify-binary)

* [crowdstrike-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-network-connection)

* [crowdstrike-process-created-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-process-created-1)

* [crowdstrike-process-created-2](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-process-created-2)

* [crowdstrike-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-process-created)

* [crowdstrike-process-network](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-process-network)

* [crowdstrike-security-alert-4](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-security-alert-4)

* [crowdstrike-service-created-1](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-service-created-1)

* [crowdstrike-service-created](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-service-created)

* [crowdstrike-usb-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-usb-alert)

* [crowdstrike-usb-connect](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-usb-connect)

* [crowdstrike-usb-disconnect](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-usb-disconnect)

* [crowdstrike-win-task-created](https://github.com/ExabeamLabs/Content-Doc/search?q=crowdstrike-win-task-created)

* [cws-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=cws-proxy-1)

* [cws-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=cws-proxy)

* [d-juniper-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=d-juniper-proxy)

* [defender-atp-security-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-1)

* [defender-atp-security-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-3)

* [defender-atp-security-alert-4](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-4)

* [defender-atp-security-alert-5](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-5)

* [defender-atp-security-alert-6](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-6)

* [defender-atp-security-alert-7](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-7)

* [defender-atp-security-alert-8](https://github.com/ExabeamLabs/Content-Doc/search?q=defender-atp-security-alert-8)

* [dell-file-operations-1](https://github.com/ExabeamLabs/Content-Doc/search?q=dell-file-operations-1)

* [dell-file-operations-2](https://github.com/ExabeamLabs/Content-Doc/search?q=dell-file-operations-2)

* [dell-file-operations-3](https://github.com/ExabeamLabs/Content-Doc/search?q=dell-file-operations-3)

* [dell-file-operations-4](https://github.com/ExabeamLabs/Content-Doc/search?q=dell-file-operations-4)

* [dell-file-remote-access](https://github.com/ExabeamLabs/Content-Doc/search?q=dell-file-remote-access)

* [digital-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=digital-web-activity)

* [edgewave-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=edgewave-web-activity)

* [elk-cisco-wsa-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=elk-cisco-wsa-web-activity)

* [estreamer-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=estreamer-dns-query)

* [exa-cor-rule-alerts](https://github.com/ExabeamLabs/Content-Doc/search?q=exa-cor-rule-alerts)

* [exchange-dlp-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-alert-1)

* [exchange-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-alert)

* [exchange-dlp-email-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-alert-1)

* [exchange-dlp-email-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-alert-2)

* [exchange-dlp-email-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-alert-3)

* [exchange-dlp-email-alert-resolved](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-alert-resolved)

* [exchange-dlp-email-in-1](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-in-1)

* [exchange-dlp-email-internal](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-internal)

* [exchange-dlp-email-out-1](https://github.com/ExabeamLabs/Content-Doc/search?q=exchange-dlp-email-out-1)

* [f5-asm-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=f5-asm-alert-1)

* [f5-asm-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=f5-asm-alert)

* [f5-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=f5-web-activity)

* [falcon-dns-request](https://github.com/ExabeamLabs/Content-Doc/search?q=falcon-dns-request)

* [fidelis-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=fidelis-email-alert)

* [fireeye-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=fireeye-dlp-email)

* [fireeye-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=fireeye-web-activity)

* [forcepoint-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=forcepoint-proxy-1)

* [forcepoint-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=forcepoint-proxy-2)

* [forcepoint-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=forcepoint-proxy)

* [forcepoint-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=forcepoint-web-activity-2)

* [fortinet-dlp-alert-email-1](https://github.com/ExabeamLabs/Content-Doc/search?q=fortinet-dlp-alert-email-1)

* [fortinet-dlp-alert-email](https://github.com/ExabeamLabs/Content-Doc/search?q=fortinet-dlp-alert-email)

* [fortinet-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=fortinet-network-connection)

* [fortinet-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=fortinet-web-activity-1)

* [fortinet-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=fortinet-web-activity)

* [googlecloud-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=googlecloud-app-activity)

* [gravityzone-security-alert-aph](https://github.com/ExabeamLabs/Content-Doc/search?q=gravityzone-security-alert-aph)

* [gravityzone-security-alert-av](https://github.com/ExabeamLabs/Content-Doc/search?q=gravityzone-security-alert-av)

* [gravityzone-security-alert-avc](https://github.com/ExabeamLabs/Content-Doc/search?q=gravityzone-security-alert-avc)

* [gravityzone-security-alert-hd](https://github.com/ExabeamLabs/Content-Doc/search?q=gravityzone-security-alert-hd)

* [gravityzone-security-alert-new-login](https://github.com/ExabeamLabs/Content-Doc/search?q=gravityzone-security-alert-new-login)

* [gravityzone-web-activity-denied](https://github.com/ExabeamLabs/Content-Doc/search?q=gravityzone-web-activity-denied)

* [ibm-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=ibm-web-activity)

* [ifilter-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=ifilter-web-activity)

* [iguard-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=iguard-dlp-alert)

* [imss-dlp-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=imss-dlp-alert-1)

* [imss-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=imss-dlp-alert)

* [imss-security-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=imss-security-alert-1)

* [imss-security-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=imss-security-alert-2)

* [imss-security-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=imss-security-alert-3)

* [imss-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=imss-security-alert)

* [imsva-dlp-email-in-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=imsva-dlp-email-in-failed)

* [imsva-dlp-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=imsva-dlp-email-in)

* [imsva-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=imsva-dlp-email-out)

* [ironport-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-1)

* [ironport-proxy-3](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-3)

* [ironport-proxy-4](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-4)

* [ironport-proxy-parser-10](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-10)

* [ironport-proxy-parser-11](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-11)

* [ironport-proxy-parser-12](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-12)

* [ironport-proxy-parser-13](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-13)

* [ironport-proxy-parser-14](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-14)

* [ironport-proxy-parser-3](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-3)

* [ironport-proxy-parser-4](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-4)

* [ironport-proxy-parser-5](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-5)

* [ironport-proxy-parser-6](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-6)

* [ironport-proxy-parser-7](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-7)

* [ironport-proxy-parser-8](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-8)

* [ironport-proxy-parser-9](https://github.com/ExabeamLabs/Content-Doc/search?q=ironport-proxy-parser-9)

* [isilon-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=isilon-file-delete)

* [isilon-file-permission-change](https://github.com/ExabeamLabs/Content-Doc/search?q=isilon-file-permission-change)

* [isilon-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=isilon-file-read)

* [isilon-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=isilon-file-write)

* [json-4771](https://github.com/ExabeamLabs/Content-Doc/search?q=json-4771)

* [json-azure-storage-access](https://github.com/ExabeamLabs/Content-Doc/search?q=json-azure-storage-access)

* [json-bro-dns-query-2](https://github.com/ExabeamLabs/Content-Doc/search?q=json-bro-dns-query-2)

* [json-bro-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=json-bro-email-in)

* [json-cisco-cloudlock-dlp](https://github.com/ExabeamLabs/Content-Doc/search?q=json-cisco-cloudlock-dlp)

* [json-dell-file-operations](https://github.com/ExabeamLabs/Content-Doc/search?q=json-dell-file-operations)

* [json-exchange-email](https://github.com/ExabeamLabs/Content-Doc/search?q=json-exchange-email)

* [json-exchange-scanmail-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=json-exchange-scanmail-alert)

* [json-microsoft-app-activity-19](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-app-activity-19)

* [json-microsoft-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-dns-query)

* [json-microsoft-mcas-anomaly](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-mcas-anomaly)

* [json-microsoft-mcas-anubis](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-mcas-anubis)

* [json-microsoft-mcas-cabinet](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-mcas-cabinet)

* [json-microsoft-o365-alert-12](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-o365-alert-12)

* [json-microsoft-o365-alert-13](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-o365-alert-13)

* [json-microsoft-o365-alert-14](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-o365-alert-14)

* [json-microsoft-o365-alert-15](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-o365-alert-15)

* [json-microsoft-o365-alert-16](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-o365-alert-16)

* [json-microsoft-o365-alert-17](https://github.com/ExabeamLabs/Content-Doc/search?q=json-microsoft-o365-alert-17)

* [json-mwg-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=json-mwg-web-activity)

* [json-o365-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=json-o365-dlp-email)

* [json-okta-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-app-login-1)

* [json-okta-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-app-login)

* [json-okta-authentication-failed-3](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-authentication-failed-3)

* [json-okta-authentication-failed-4](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-authentication-failed-4)

* [json-okta-authentication-failed-5](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-authentication-failed-5)

* [json-okta-authentication-success](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-authentication-success)

* [json-okta-failed-app-login-4](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-failed-app-login-4)

* [json-okta-failed-app-login-5](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-failed-app-login-5)

* [json-okta-failed-app-login-6](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-failed-app-login-6)

* [json-okta-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=json-okta-security-alert)

* [json-process-created-1](https://github.com/ExabeamLabs/Content-Doc/search?q=json-process-created-1)

* [json-s-proofpoint-email-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=json-s-proofpoint-email-alert-2)

* [json-zeek-kerberos](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek-kerberos)

* [json-zeek_dce_rpc](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_dce_rpc)

* [json-zeek_dhcp](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_dhcp)

* [json-zeek_dns](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_dns)

* [json-zeek_files](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_files)

* [json-zeek_ntlm](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_ntlm)

* [json-zeek_ssl](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_ssl)

* [json-zeek_weird](https://github.com/ExabeamLabs/Content-Doc/search?q=json-zeek_weird)

* [juniper-access-control](https://github.com/ExabeamLabs/Content-Doc/search?q=juniper-access-control)

* [juniper-owa](https://github.com/ExabeamLabs/Content-Doc/search?q=juniper-owa)

* [juniper-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=juniper-web-activity-1)

* [juniper-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=juniper-web-activity-2)

* [l-ironport-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=l-ironport-dlp-email-alert)

* [lastpass-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=lastpass-app-activity)

* [leef-bit9-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-bit9-security-alert)

* [leef-carbonblack-file-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-carbonblack-file-alert)

* [leef-carbonblack-local-logon-1](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-carbonblack-local-logon-1)

* [leef-carbonblack-local-logon-2](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-carbonblack-local-logon-2)

* [leef-carbonblack-workstation-locked](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-carbonblack-workstation-locked)

* [leef-carbonblack-workstation-unlocked](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-carbonblack-workstation-unlocked)

* [leef-cbdef-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-cbdef-security-alert)

* [leef-digitalguardian-dlp-email-alert-out-1](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-digitalguardian-dlp-email-alert-out-1)

* [leef-digitalguardian-dlp-email-alert-out](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-digitalguardian-dlp-email-alert-out)

* [leef-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-dns-query)

* [leef-incapsula-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-incapsula-web-activity)

* [leef-mwg-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-mwg-proxy)

* [leef-pan-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-pan-proxy)

* [leef-pan-virus-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=leef-pan-virus-alert)

* [logrhythm-0365-account-password-change](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-0365-account-password-change)

* [logrhythm-0365-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-0365-app-login)

* [logrhythm-0365-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-0365-failed-app-login)

* [logrhythm-o365-file-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-activity)

* [logrhythm-o365-file-delete-2](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-delete-2)

* [logrhythm-o365-file-delete-3](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-delete-3)

* [logrhythm-o365-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-delete)

* [logrhythm-o365-file-read-2](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read-2)

* [logrhythm-o365-file-read-3](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read-3)

* [logrhythm-o365-file-read-4](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read-4)

* [logrhythm-o365-file-read-5](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read-5)

* [logrhythm-o365-file-read-6](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read-6)

* [logrhythm-o365-file-read-7](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read-7)

* [logrhythm-o365-file-read](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-read)

* [logrhythm-o365-file-upload](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-upload)

* [logrhythm-o365-file-write-2](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-2)

* [logrhythm-o365-file-write-3](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-3)

* [logrhythm-o365-file-write-4](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-4)

* [logrhythm-o365-file-write-5](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-5)

* [logrhythm-o365-file-write-6](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-6)

* [logrhythm-o365-file-write-7](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-7)

* [logrhythm-o365-file-write-8](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write-8)

* [logrhythm-o365-file-write](https://github.com/ExabeamLabs/Content-Doc/search?q=logrhythm-o365-file-write)

* [mcafee-dlp-email-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=mcafee-dlp-email-alert-1)

* [mcafee-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=mcafee-dlp-email-alert)

* [mcas-security-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=mcas-security-alert-1)

* [meraki-web-activity-denied](https://github.com/ExabeamLabs/Content-Doc/search?q=meraki-web-activity-denied)

* [messagelabs-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=messagelabs-email-in)

* [messagelabs-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=messagelabs-email-out)

* [microsoft-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-10)

* [microsoft-app-activity-11](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-11)

* [microsoft-app-activity-12](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-12)

* [microsoft-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-1)

* [microsoft-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-2)

* [microsoft-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-4)

* [microsoft-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-5)

* [microsoft-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-6)

* [microsoft-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-7)

* [microsoft-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-8)

* [microsoft-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-app-activity-9)

* [microsoft-cloud-app-security-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-cloud-app-security-alert-1)

* [microsoft-cloud-app-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=microsoft-cloud-app-security-alert)

* [mobileiron-security-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=mobileiron-security-alert)

* [ms-azure-signin-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=ms-azure-signin-app-login)

* [mwg-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=mwg-proxy-1)

* [mwg-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=mwg-proxy-2)

* [mwg-proxy-3](https://github.com/ExabeamLabs/Content-Doc/search?q=mwg-proxy-3)

* [n-cef-bluecoat-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=n-cef-bluecoat-proxy)

* [n-forwarded-cef-trendmicro-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=n-forwarded-cef-trendmicro-web-activity-1)

* [n-forwarded-cef-trendmicro-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=n-forwarded-cef-trendmicro-web-activity-2)

* [n-forwarded-cef-trendmicro-web-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=n-forwarded-cef-trendmicro-web-activity-3)

* [n-mwg-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=n-mwg-proxy)

* [named-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=named-dns-query)

* [netiq-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=netiq-app-login)

* [netscaler-cef-vpn-start](https://github.com/ExabeamLabs/Content-Doc/search?q=netscaler-cef-vpn-start)

* [netscaler-failed-vpn-login](https://github.com/ExabeamLabs/Content-Doc/search?q=netscaler-failed-vpn-login)

* [netscaler-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=netscaler-web-activity-1)

* [netscaler-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=netscaler-web-activity)

* [netscope-dlp-alert-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=netscope-dlp-alert-activity)

* [netskope-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=netskope-activity)

* [netskope-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=netskope-web-activity)

* [nxlog-json-4726](https://github.com/ExabeamLabs/Content-Doc/search?q=nxlog-json-4726)

* [o365-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-activity-3)

* [o365-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-email-alert)

* [o365-inbox-rules-move-to-folder](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-inbox-rules-move-to-folder)

* [o365-mal-url-click](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-mal-url-click)

* [o365-phishing-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-phishing-alert)

* [o365-powerbi-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-powerbi-activity)

* [o365-sharepoint-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-sharepoint-activity)

* [o365-teams-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-teams-activity-1)

* [o365-teams-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=o365-teams-app-login)

* [okta-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=okta-app-login-1)

* [oracle-access-manager](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-access-manager)

* [oracle-avdf-database-login](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-avdf-database-login)

* [oracle-avdf-database-query](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-avdf-database-query)

* [oracle-database-access-1](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-database-access-1)

* [oracle-database-login](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-database-login)

* [oracle-db-access-1](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-access-1)

* [oracle-db-access](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-access)

* [oracle-db-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-login-1)

* [oracle-db-login](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-login)

* [oracle-db-query-1](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-query-1)

* [oracle-db-query-2](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-query-2)

* [oracle-db-query-3](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-query-3)

* [oracle-db-query](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-query)

* [oracle-db-update](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-db-update)

* [oracle-public-cloud-netflow-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=oracle-public-cloud-netflow-connection)

* [pan-virus-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=pan-virus-alert)

* [ping-authentication-successful](https://github.com/ExabeamLabs/Content-Doc/search?q=ping-authentication-successful)

* [postfix-dlp-email-from](https://github.com/ExabeamLabs/Content-Doc/search?q=postfix-dlp-email-from)

* [proofpoint-dlp-email-from](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-dlp-email-from)

* [proofpoint-email-1](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-email-1)

* [proofpoint-email-2](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-email-2)

* [proofpoint-email-3](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-email-3)

* [proofpoint-email-4](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-email-4)

* [proofpoint-email-5](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-email-5)

* [proofpoint-email](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-email)

* [proofpoint-m1](https://github.com/ExabeamLabs/Content-Doc/search?q=proofpoint-m1)

* [q-bit9-epp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=q-bit9-epp-alert)

* [q-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=q-dlp-alert)

* [q-exchange-dlp-email-in-1](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-in-1)

* [q-exchange-dlp-email-in-2](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-in-2)

* [q-exchange-dlp-email-in-3](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-in-3)

* [q-exchange-dlp-email-in-4](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-in-4)

* [q-exchange-dlp-email-in-5](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-in-5)

* [q-exchange-dlp-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-in)

* [q-exchange-dlp-email-out-1](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-out-1)

* [q-exchange-dlp-email-out-2](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-out-2)

* [q-exchange-dlp-email-out-3](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-out-3)

* [q-exchange-dlp-email-out-4](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-out-4)

* [q-exchange-dlp-email-out-5](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-out-5)

* [q-exchange-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=q-exchange-dlp-email-out)

* [q-kiteworks-email-out-1](https://github.com/ExabeamLabs/Content-Doc/search?q=q-kiteworks-email-out-1)

* [q-kiteworks-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=q-kiteworks-email-out)

* [q-member-removed-2008](https://github.com/ExabeamLabs/Content-Doc/search?q=q-member-removed-2008)

* [q-o365-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=q-o365-dlp-email)

* [q-oam-app-activity-10](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-10)

* [q-oam-app-activity-11](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-11)

* [q-oam-app-activity-12](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-12)

* [q-oam-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-2)

* [q-oam-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-3)

* [q-oam-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-4)

* [q-oam-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-5)

* [q-oam-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-6)

* [q-oam-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-7)

* [q-oam-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-8)

* [q-oam-app-activity-9](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-activity-9)

* [q-oam-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-app-login)

* [q-oam-auth-successful](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oam-auth-successful)

* [q-okta-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-app-login-1)

* [q-okta-app-login-2](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-app-login-2)

* [q-okta-app-login-3](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-app-login-3)

* [q-okta-app-login-4](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-app-login-4)

* [q-okta-app-login-5](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-app-login-5)

* [q-okta-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-app-login)

* [q-okta-failed-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-failed-app-login-1)

* [q-okta-failed-app-login-2](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-failed-app-login-2)

* [q-okta-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=q-okta-failed-app-login)

* [q-oracle-db-login](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oracle-db-login)

* [q-oracle-db-query](https://github.com/ExabeamLabs/Content-Doc/search?q=q-oracle-db-query)

* [q-process-alert-carbonblack-1](https://github.com/ExabeamLabs/Content-Doc/search?q=q-process-alert-carbonblack-1)

* [q-process-alert-carbonblack](https://github.com/ExabeamLabs/Content-Doc/search?q=q-process-alert-carbonblack)

* [q-proofpoint-email](https://github.com/ExabeamLabs/Content-Doc/search?q=q-proofpoint-email)

* [q-sendmail-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=q-sendmail-dlp-email-alert)

* [q-symantec-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=q-symantec-dlp-email-out)

* [q-vontu-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=q-vontu-dlp-alert)

* [q-wsa-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=q-wsa-proxy)

* [q-zscaler-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=q-zscaler-web-activity)

* [r-syslog-vontu-dlp-1](https://github.com/ExabeamLabs/Content-Doc/search?q=r-syslog-vontu-dlp-1)

* [r-syslog-vontu-dlp](https://github.com/ExabeamLabs/Content-Doc/search?q=r-syslog-vontu-dlp)

* [raw-4624-10](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4624-10)

* [raw-4625](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4625)

* [raw-4648-5](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4648-5)

* [raw-4662-1](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4662-1)

* [raw-4662](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4662)

* [raw-4663](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4663)

* [raw-4672-1](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4672-1)

* [raw-4672-3](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4672-3)

* [raw-4673-2](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4673-2)

* [raw-4674-4](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4674-4)

* [raw-4719](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4719)

* [raw-4723](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4723)

* [raw-4724](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4724)

* [raw-4742](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4742)

* [raw-4768-5](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4768-5)

* [raw-4768](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4768)

* [raw-4769-7](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4769-7)

* [raw-4769](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4769)

* [raw-4771-2](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4771-2)

* [raw-4771](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4771)

* [raw-4776-5](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4776-5)

* [raw-4776](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-4776)

* [raw-5136](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-5136)

* [raw-5140-2](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-5140-2)

* [raw-5140](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-5140)

* [raw-5143](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-5143)

* [raw-5145-11](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-5145-11)

* [raw-7045](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-7045)

* [raw-asa-113005](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-asa-113005)

* [raw-juniper-nwc-vpn-connected](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-juniper-nwc-vpn-connected)

* [raw-member-added-2003](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-member-added-2003)

* [raw-member-added-2008](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-member-added-2008)

* [raw-member-removed-2008-2](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-member-removed-2008-2)

* [raw-member-removed-2008](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-member-removed-2008)

* [raw-netscaler-vpn-start](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-netscaler-vpn-start)

* [raw-powershell-600](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-powershell-600)

* [raw-ssh-login](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-ssh-login)

* [raw-unix-password-change](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-unix-password-change)

* [raw-unix-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-unix-process-created)

* [raw-unix-su](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-unix-su)

* [raw-windows-account-4725](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-windows-account-4725)

* [raw-windows-account-4726](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-windows-account-4726)

* [raw-windows-account-4740](https://github.com/ExabeamLabs/Content-Doc/search?q=raw-windows-account-4740)

* [rsa-auth-successful-1](https://github.com/ExabeamLabs/Content-Doc/search?q=rsa-auth-successful-1)

* [rsa-auth-successful-2](https://github.com/ExabeamLabs/Content-Doc/search?q=rsa-auth-successful-2)

* [rsa-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=rsa-dlp-email-alert)

* [s-O365-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=s-O365-dlp-email)

* [s-O365-email](https://github.com/ExabeamLabs/Content-Doc/search?q=s-O365-email)

* [s-aws-cloudtrail-activity-json](https://github.com/ExabeamLabs/Content-Doc/search?q=s-aws-cloudtrail-activity-json)

* [s-aws-cloudtrail-assumedrole-json](https://github.com/ExabeamLabs/Content-Doc/search?q=s-aws-cloudtrail-assumedrole-json)

* [s-azure-ad-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-azure-ad-app-login)

* [s-azure-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-azure-app-login)

* [s-azure-storage-access](https://github.com/ExabeamLabs/Content-Doc/search?q=s-azure-storage-access)

* [s-bit9-epp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-bit9-epp-alert)

* [s-brightmail-email](https://github.com/ExabeamLabs/Content-Doc/search?q=s-brightmail-email)

* [s-bro-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-bro-web-activity)

* [s-carbonblack-process-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-carbonblack-process-alert)

* [s-checkpoint-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=s-checkpoint-proxy)

* [s-codegreen-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=s-codegreen-dlp-email-out)

* [s-crowdstrike-app-dll-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-crowdstrike-app-dll-alert)

* [s-crowdstrike-app-ransomware](https://github.com/ExabeamLabs/Content-Doc/search?q=s-crowdstrike-app-ransomware)

* [s-cws-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=s-cws-proxy)

* [s-digitalguardian-dlp-email-out-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-digitalguardian-dlp-email-out-1)

* [s-digitalguardian-dlp-email-out-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-digitalguardian-dlp-email-out-2)

* [s-digitalguardian-dlp-email-out-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-digitalguardian-dlp-email-out-3)

* [s-digitalguardian-dlp-email-out-4](https://github.com/ExabeamLabs/Content-Doc/search?q=s-digitalguardian-dlp-email-out-4)

* [s-dlp-email-out](https://github.com/ExabeamLabs/Content-Doc/search?q=s-dlp-email-out)

* [s-dropbox-devices-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-dropbox-devices-activity)

* [s-f5-dns-response](https://github.com/ExabeamLabs/Content-Doc/search?q=s-f5-dns-response)

* [s-fireeye-hx-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-fireeye-hx-alert-1)

* [s-fireeye-hx-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-fireeye-hx-alert-2)

* [s-fireeye-hx-alert-hx](https://github.com/ExabeamLabs/Content-Doc/search?q=s-fireeye-hx-alert-hx)

* [s-fireeye-hx-alert-s-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-fireeye-hx-alert-s-1)

* [s-fireeye-hx-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-fireeye-hx-alert)

* [s-github-unicorn-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-github-unicorn-activity)

* [s-ironport-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-ironport-dlp-email-alert)

* [s-ironport-email-recipient](https://github.com/ExabeamLabs/Content-Doc/search?q=s-ironport-email-recipient)

* [s-juniper-pulse-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-juniper-pulse-activity)

* [s-kaspersky-endpoint-security](https://github.com/ExabeamLabs/Content-Doc/search?q=s-kaspersky-endpoint-security)

* [s-lanscope-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-lanscope-web-activity)

* [s-lanscopecat-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-lanscopecat-web-activity)

* [s-mcafee-epo-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mcafee-epo-dlp-alert)

* [s-microsoft-isa-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-microsoft-isa-proxy-1)

* [s-microsoft-isa-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-microsoft-isa-proxy-2)

* [s-microsoft-isa-proxy-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-microsoft-isa-proxy-3)

* [s-microsoft-print-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-microsoft-print-activity-1)

* [s-mimecast-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mimecast-dlp-email)

* [s-mwg-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mwg-proxy-1)

* [s-mwg-proxy-3-denied](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mwg-proxy-3-denied)

* [s-mwg-proxy-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mwg-proxy-3)

* [s-mwg-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mwg-proxy)

* [s-mwg-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-mwg-web-activity)

* [s-netscaler-auth-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=s-netscaler-auth-failed)

* [s-oam-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oam-app-login-1)

* [s-oam-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oam-app-login)

* [s-okta-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-okta-app-login-1)

* [s-okta-app-login-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-okta-app-login-2)

* [s-okta-app-login-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-okta-app-login-3)

* [s-okta-app-login-4](https://github.com/ExabeamLabs/Content-Doc/search?q=s-okta-app-login-4)

* [s-okta-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-okta-app-login)

* [s-okta-failed-login-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-okta-failed-login-3)

* [s-oracle-db-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-activity-2)

* [s-oracle-db-execute-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-execute-1)

* [s-oracle-db-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-login-1)

* [s-oracle-db-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-login)

* [s-oracle-db-logon](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-logon)

* [s-oracle-db-query](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-query)

* [s-oracle-db-select-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-oracle-db-select-1)

* [s-pantraps-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-pantraps-alert)

* [s-phantom-dlp-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=s-phantom-dlp-email-in)

* [s-postfix-dlp-email-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-postfix-dlp-email-1)

* [s-postfix-dlp-email](https://github.com/ExabeamLabs/Content-Doc/search?q=s-postfix-dlp-email)

* [s-process-alert-carbonblack-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-process-alert-carbonblack-1)

* [s-process-alert-carbonblack-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-process-alert-carbonblack-2)

* [s-process-alert-carbonblack](https://github.com/ExabeamLabs/Content-Doc/search?q=s-process-alert-carbonblack)

* [s-process-created-carbonblack](https://github.com/ExabeamLabs/Content-Doc/search?q=s-process-created-carbonblack)

* [s-process-network-carbonblack](https://github.com/ExabeamLabs/Content-Doc/search?q=s-process-network-carbonblack)

* [s-proofpoint-email-alert-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-proofpoint-email-alert-2)

* [s-proofpoint-email-in-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-proofpoint-email-in-1)

* [s-proofpoint-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=s-proofpoint-email-in)

* [s-safesend-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-safesend-dlp-email-alert)

* [s-salesforce-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-salesforce-app-login)

* [s-sendmail-email-from](https://github.com/ExabeamLabs/Content-Doc/search?q=s-sendmail-email-from)

* [s-skyfence-login](https://github.com/ExabeamLabs/Content-Doc/search?q=s-skyfence-login)

* [s-splunkstream-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=s-splunkstream-dns-query)

* [s-ssh-login-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=s-ssh-login-failed)

* [s-symantec-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-symantec-dlp-alert)

* [s-symantec-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-symantec-email-alert)

* [s-symantec-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-symantec-web-activity-1)

* [s-symantec-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-symantec-web-activity)

* [s-trendmicro-security-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-trendmicro-security-alert-3)

* [s-vontu-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=s-vontu-dlp-email-alert)

* [s-vontu-email-dlp](https://github.com/ExabeamLabs/Content-Doc/search?q=s-vontu-email-dlp)

* [s-zscaler-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=s-zscaler-web-activity-1)

* [s-zscaler-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=s-zscaler-web-activity-2)

* [s-zscaler-web-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=s-zscaler-web-activity-3)

* [s-zscaler-web-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=s-zscaler-web-activity-4)

* [s-zscaler-web-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=s-zscaler-web-activity-5)

* [s-zscaler-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=s-zscaler-web-activity)

* [sangfor-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=sangfor-web-activity)

* [secureauth-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=secureauth-app-login)

* [secureauth-auth-successful-1](https://github.com/ExabeamLabs/Content-Doc/search?q=secureauth-auth-successful-1)

* [secureauth-auth-successful](https://github.com/ExabeamLabs/Content-Doc/search?q=secureauth-auth-successful)

* [sendmail-email-from](https://github.com/ExabeamLabs/Content-Doc/search?q=sendmail-email-from)

* [sentinelone-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-dns-query)

* [sentinelone-dns-response-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-dns-response-1)

* [sentinelone-dns-response](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-dns-response)

* [sentinelone-file-create-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-file-create-1)

* [sentinelone-file-create](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-file-create)

* [sentinelone-file-delete-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-file-delete-1)

* [sentinelone-file-delete](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-file-delete)

* [sentinelone-file-modify-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-file-modify-1)

* [sentinelone-file-modify](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-file-modify)

* [sentinelone-network-connection-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-network-connection-1)

* [sentinelone-network-connection](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-network-connection)

* [sentinelone-process-created-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-process-created-1)

* [sentinelone-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-process-created)

* [sentinelone-task-register](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-task-register)

* [sentinelone-task-update-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-task-update-1)

* [sentinelone-task-update-2](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-task-update-2)

* [sentinelone-task-update](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-task-update)

* [sentinelone-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-web-activity-1)

* [sentinelone-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-web-activity-2)

* [sentinelone-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=sentinelone-web-activity)

* [sfdc-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=sfdc-app-activity)

* [sfdc-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sfdc-app-login-1)

* [sfdc-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=sfdc-app-login)

* [siebel-db-query](https://github.com/ExabeamLabs/Content-Doc/search?q=siebel-db-query)

* [sk4-workday-app-auth-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=sk4-workday-app-auth-failed)

* [sk4-workday-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=sk4-workday-app-login)

* [sk4-workday-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=sk4-workday-failed-app-login)

* [skyformation-cloudflare-waf-1](https://github.com/ExabeamLabs/Content-Doc/search?q=skyformation-cloudflare-waf-1)

* [skyformation-cloudflare-waf-2](https://github.com/ExabeamLabs/Content-Doc/search?q=skyformation-cloudflare-waf-2)

* [skyformation-cloudflare-waf](https://github.com/ExabeamLabs/Content-Doc/search?q=skyformation-cloudflare-waf)

* [slack-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-1)

* [slack-app-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-2)

* [slack-app-activity-3](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-3)

* [slack-app-activity-4](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-4)

* [slack-app-activity-5](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-5)

* [slack-app-activity-6](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-6)

* [slack-app-activity-7](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-7)

* [slack-app-activity-8](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-activity-8)

* [slack-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-app-login)

* [slack-file-download](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-file-download)

* [slack-file-upload](https://github.com/ExabeamLabs/Content-Doc/search?q=slack-file-upload)

* [solaris-audit-process](https://github.com/ExabeamLabs/Content-Doc/search?q=solaris-audit-process)

* [sonicwall-fw-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=sonicwall-fw-web-activity)

* [sophos-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sophos-proxy-1)

* [sophos-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=sophos-proxy-2)

* [sophos-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=sophos-proxy)

* [sourcefire-network-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sourcefire-network-alert-1)

* [sourcefire-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=sourcefire-proxy-1)

* [sourcefire-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=sourcefire-proxy)

* [squid-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=squid-web-activity-1)

* [squid-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=squid-web-activity-2)

* [squid-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=squid-web-activity)

* [symantec-app-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-app-activity)

* [symantec-cloud-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-cloud-activity)

* [symantec-dlp-cit-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-dlp-cit-alert)

* [symantec-dlp-email-alert-in](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-dlp-email-alert-in)

* [symantec-email-alert-out](https://github.com/ExabeamLabs/Content-Doc/search?q=symantec-email-alert-out)

* [syslog-4776-multiline](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-4776-multiline)

* [syslog-barracuda-email](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-barracuda-email)

* [syslog-bit9-file-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-bit9-file-alert)

* [syslog-brightmail-email-in](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-brightmail-email-in)

* [syslog-checkpoint-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-checkpoint-app-login-1)

* [syslog-checkpoint-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-checkpoint-app-login)

* [syslog-cisco-wsa-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-cisco-wsa-web-activity)

* [syslog-f5-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-f5-dns-query)

* [syslog-f5-dns-response](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-f5-dns-response)

* [syslog-mcafee-dlp-email-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-mcafee-dlp-email-alert)

* [syslog-mcafee-network-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-mcafee-network-alert)

* [syslog-rsa-auth-failed](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-rsa-auth-failed)

* [syslog-rsa-auth-successful](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-rsa-auth-successful)

* [syslog-symantec-dlp-alert-1](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-symantec-dlp-alert-1)

* [syslog-symantec-dlp-alert-3](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-symantec-dlp-alert-3)

* [syslog-symantec-dlp-alert-4](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-symantec-dlp-alert-4)

* [syslog-symantec-dlp-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=syslog-symantec-dlp-alert)

* [tfcs-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=tfcs-web-activity)

* [tmg-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=tmg-proxy)

* [trend-micro-alert-6](https://github.com/ExabeamLabs/Content-Doc/search?q=trend-micro-alert-6)

* [trend-micro-alert-7](https://github.com/ExabeamLabs/Content-Doc/search?q=trend-micro-alert-7)

* [trendmicro-cef-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=trendmicro-cef-alert)

* [trendmicro-cef-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=trendmicro-cef-web-activity)

* [u-okta-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=u-okta-app-login)

* [u-okta-failed-app-login](https://github.com/ExabeamLabs/Content-Doc/search?q=u-okta-failed-app-login)

* [unix-failed-logon-3](https://github.com/ExabeamLabs/Content-Doc/search?q=unix-failed-logon-3)

* [virtru-email-encryption-alert](https://github.com/ExabeamLabs/Content-Doc/search?q=virtru-email-encryption-alert)

* [vmware-esxi-login](https://github.com/ExabeamLabs/Content-Doc/search?q=vmware-esxi-login)

* [vmware-remote-logon-1](https://github.com/ExabeamLabs/Content-Doc/search?q=vmware-remote-logon-1)

* [vontu-dlp](https://github.com/ExabeamLabs/Content-Doc/search?q=vontu-dlp)

* [vontu-email-dlp](https://github.com/ExabeamLabs/Content-Doc/search?q=vontu-email-dlp)

* [watchguard-web-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=watchguard-web-activity-1)

* [watchguard-web-activity-2](https://github.com/ExabeamLabs/Content-Doc/search?q=watchguard-web-activity-2)

* [watchguard-web-activity-deny](https://github.com/ExabeamLabs/Content-Doc/search?q=watchguard-web-activity-deny)

* [watchguard-web-activity-drop](https://github.com/ExabeamLabs/Content-Doc/search?q=watchguard-web-activity-drop)

* [watchguard-web-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=watchguard-web-activity)

* [weblogin-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=weblogin-app-activity-1)

* [websense-dlp-email-alert-in](https://github.com/ExabeamLabs/Content-Doc/search?q=websense-dlp-email-alert-in)

* [websense-proxy-1](https://github.com/ExabeamLabs/Content-Doc/search?q=websense-proxy-1)

* [websense-proxy-2](https://github.com/ExabeamLabs/Content-Doc/search?q=websense-proxy-2)

* [websense-proxy-3](https://github.com/ExabeamLabs/Content-Doc/search?q=websense-proxy-3)

* [websense-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=websense-proxy)

* [windows-dns-query-2](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-dns-query-2)

* [windows-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-dns-query)

* [windows-dns-response](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-dns-response)

* [windows-xml-4674](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-4674)

* [windows-xml-4700](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-4700)

* [windows-xml-4720](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-4720)

* [windows-xml-4722](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-4722)

* [windows-xml-4742](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-4742)

* [windows-xml-member-added-2008](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-member-added-2008)

* [windows-xml-powershell-800](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-powershell-800)

* [windows-xml-powershell-process-created-1](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-powershell-process-created-1)

* [windows-xml-powershell-process-created-2](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-powershell-process-created-2)

* [windows-xml-powershell-process-created](https://github.com/ExabeamLabs/Content-Doc/search?q=windows-xml-powershell-process-created)

* [workday-app-activity-1](https://github.com/ExabeamLabs/Content-Doc/search?q=workday-app-activity-1)

* [workday-app-login-1](https://github.com/ExabeamLabs/Content-Doc/search?q=workday-app-login-1)

* [xml-5143](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-5143)

* [xml-member-removed-2008](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-member-removed-2008)

* [xml-microsoft-dns-query](https://github.com/ExabeamLabs/Content-Doc/search?q=xml-microsoft-dns-query)

* [zoom-login](https://github.com/ExabeamLabs/Content-Doc/search?q=zoom-login)

* [zoom-operations-activity](https://github.com/ExabeamLabs/Content-Doc/search?q=zoom-operations-activity)

* [zscaler-proxy](https://github.com/ExabeamLabs/Content-Doc/search?q=zscaler-proxy)

* [zscaler-status](https://github.com/ExabeamLabs/Content-Doc/search?q=zscaler-status)

* [zscaler-vpn-user](https://github.com/ExabeamLabs/Content-Doc/search?q=zscaler-vpn-user)


#### Deprecated Parsers
* s-crowdstrike-auth-failed


Models
------
* [New](#New-Models)

* [Updated](#Updated-Models)

* [Deprecated](#Deprecated-Models)

#### New Models
* [APP-UOs-New](https://github.com/ExabeamLabs/Content-Doc/search?q=APP-UOs-New) &#8211; OS and Browser from user agent

* [VPN29-New](https://github.com/ExabeamLabs/Content-Doc/search?q=VPN29-New) &#8211; VPN Operating System

* [WEB-GUa-Browser-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-GUa-Browser-New) &#8211; Top web browsers being used by peer group

* [WEB-GUa-OS-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-GUa-OS-New) &#8211; Top operating systems being used to connect to the web for peer group

* [WEB-OUa-Browser-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-OUa-Browser-New) &#8211; Top web browsers being used in this organization

* [WEB-OUa-OS-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-OUa-OS-New) &#8211; Top operating systems being used to connect to the web for organization

* [WEB-OsUa-MobileBrowser-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-OsUa-MobileBrowser-New) &#8211; Top mobile apps/web browsers being used in the organization for this type of device

* [WEB-UUa-Browser-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-UUa-Browser-New) &#8211; Top web browsers being used by user

* [WEB-UUa-MobileBrowser-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-UUa-MobileBrowser-New) &#8211; Top mobile apps/web browsers being used by user

* [WEB-UUa-OS-New](https://github.com/ExabeamLabs/Content-Doc/search?q=WEB-UUa-OS-New) &#8211; Top operating systems being used to connect to the web for user


#### Updated Models
There are no updated models in this release.

#### Deprecated Models
There are no deprecated models in this release.

Rules
-----
* [New](#New-Rules)

* [Updated](#Updated-Rules)

* [Deprecated](#Deprecated-Rules)

#### New Rules
* [A-ALERT-DL](https://github.com/ExabeamLabs/Content-Doc/search?q=A-ALERT-DL) &#8211; DL Correlation rule alert on asset


#### Updated Rules
There are no updated rules in this release.

#### Deprecated Rules
There are no deprecated rules in this release.

