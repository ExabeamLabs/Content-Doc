Vendor: VMware
==============
### Product: [Endpoint Detection and Response](../ds_vmware_endpoint_detection_and_response.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     6      |      5      |    5    |

| Event Type          | Rules    | Models |
| ---- | ---- | ------ |
| process-created     | <b>T1566.001 - T1566.001</b><br> ↳ <b>A-Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder on this asset.<br> ↳ <b>Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder.    |        |
| web-activity-denied | <b>T1534 - Internal Spearphishing</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1566.002 - Phishing: Spearphishing Link</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1598.003 - T1598.003</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1189 - Drive-by Compromise</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br><br><b>T1204.001 - T1204.001</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain |        |