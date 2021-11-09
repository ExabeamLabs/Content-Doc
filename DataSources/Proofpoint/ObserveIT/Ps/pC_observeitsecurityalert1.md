#### Parser Content
```Java
{
Name = observeit-security-alert-1
  DataType = "alert"
  Conditions = [ """"observedAt": """", """"sessionUrl": """", """"loginName": """", """"ruleCategoryName": "TRUE DIGITAL WINDOWS RULES"""" ]
}
observeit-activity = {
  Vendor = Proofpoint
  Product = ObserveIT
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"observedAt":\s{0,100}"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"applicationName":\s{0,100}"(?:[A-Fa-f:\d.]{1,2000}|({app}[^"]{1,2000}))"""",
    """"command":\s{0,100}"({command}[^",]{1,2000})"""",
    """"domainName":\s{0,100}"({domain}[^",]{1,2000})"""",
    """"endpointName":\s{0,100}"({host}[^",]{1,2000})"""",
    """"loginName":\s{0,100}"({user}[^",\s]{1,2000})"""",
    """"loginName":\s{0,100}"({user_fullname}\w+\s\w+)"""",
    """"os":\s{0,100}"({os}[^",]{1,2000})"""",
    """"remoteAddress":\s{0,100}"(?:127\.0\.0\.1|({src_ip}[A-Fa-f:\d.]{1,2000}))"""",
    """"remoteHostName":\s{0,100}"(?:\(local\)|({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[^",]{1,2000}))"""",
    """"ruleCategoryName":\s{0,100}"({alert_type}[^",]{1,2000})"""",
    """"ruleName":\s{0,100}"({alert_name}[^",]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^",]{1,2000})"""",
    """"sessionId":\s{0,100}"({session_id}[^",]{1,2000})"""",
    """"ruleDesc":\s{0,100}"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"detailsUrl":\s{0,100}"({additional_info}[^",]{1,2000})"""",
    """"sqlUserName":\s{0,100}"({db_user}[^",]{1,2000})"""",
    """"databaseName":\s{0,100}"({database_name}[^",]{1,2000})"""",
    """"id":\s{0,100}({alert_id}\d{1,100})"""
  ]}
```