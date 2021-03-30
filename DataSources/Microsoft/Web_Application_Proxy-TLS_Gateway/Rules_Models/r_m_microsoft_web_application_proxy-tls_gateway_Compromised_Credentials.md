Vendor: Microsoft
=================
### Product: [Web Application Proxy-TLS Gateway](../ds_microsoft_web_application_proxy-tls_gateway.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     1      |      1      |    1    |

| Event Type          | Rules                                                                                                                                                                                                                                                                                                                                                                                                      | Models                                                                |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| web-activity-denied | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>WEB-UU-Reputation</b>: User attempted access to a url with bad reputation<br> ↳ <b>WEB-UD-ALERT-F</b>: First security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-A</b>: Abnormal security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-N</b>: Common security alert on this malicious domain for user |  • <b>WEB-UD-ALERT</b>: Top malicious web domain accessed by the user |