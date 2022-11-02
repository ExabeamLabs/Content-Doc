#### Parser Content
```Java
{
Name = json-cybereason-security-alert
  Vendor = Cybereason
  Product = Cybereason
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"hasSuspicions": true""", """"hasMalops": true""", """"affectedMachines"""", """"affectedUsers"""" ]
  Fields = [
    """"creationTime":\s{1,20}"({time}\d{13})"""",
    """"detectionType":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"affectedMachines":\s{0,100}\{[^\}]{1,2000}?"elementType":\s{0,100}"Machine"[^\}]{1,2000}?"name":\s{0,100}"({dest_host}[^"]{1,2000})"""",
    """"affectedUsers":\s{0,100}\{[^\}]{1,2000}"elementType":\s{0,100}"User"[^\}]{1,2000}"name":\s{0,100}"((nt service|nt instans|({domain}[^\\"]{1,2000}))\\{1,2000})?(network service|system|({user}[^"]{1,2000}))"""",
    """'message':\s{0,20}'({additional_info}[^']{1,2000}?)\s{0,100}'""",
    """"elementDisplayName":\s{0,100}\{[^\}]{1,2000}"values":\s{0,100}\["{1,2000}({additional_info}[^"]{1,2000})"""",
    """"malopActivityTypes":\s{0,100}"({threat_category}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""""
  ]
  DupFields = ["alert_type->alert_name"]


}
```