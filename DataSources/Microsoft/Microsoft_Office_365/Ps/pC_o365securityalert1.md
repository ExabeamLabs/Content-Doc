#### Parser Content
```Java
{
Name = o365-security-alert-1
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"vendor": "Microsoft"""", """"riskScore":""", """"malwareStates":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"userPrincipalName":\s{0,100}"({user_email}[^"@]{1,2000}@[^"]{1,2000})""",
    """"logonIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"userStates":\s{0,100}\[.*?accountName":\s{0,100}"({user}[^",]{1,2000})""",    
    """"accountName":\s{0,100}"({user}[^"]{1,2000})""",
    """"domainName":\s{0,100}"({domain}[^"]{1,2000})""",
    """"(eventDateTime|createdDateTime|lastModifiedDateTime)":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"destinationServiceName":\s{0,100}"({app}[^"]{1,2000})""",
    """"id":\s{0,100}"({alert_id}[^"]{1,2000})""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"description":\s{0,100}"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"category":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"title":\s{0,100}"({alert_name}[^"]{1,2000}?)\s{0,100}"""",
    """"category":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"status":\s{0,100}"(unknown|({outcome}[^"]{1,2000}))""",
    """"logonLocation":\s{0,100}"({location}[^"]{1,2000})""",
  ]


}
```