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
    """exabeam_host=({host}[\w.\-]+)""",
    """"userPrincipalName":\s{0,100}"({user_email}[^"@]+@[^"]+)""",
    """"logonIp":\s{0,100}"({src_ip}[^"]+)""",
    """"userStates":\s{0,100}\[.*?accountName":\s{0,100}"({user}[^",]+)""",    
    """"accountName":\s{0,100}"({user}[^"]+)""",
    """"domainName":\s{0,100}"({domain}[^"]+)""",
    """"(eventDateTime|createdDateTime|lastModifiedDateTime)":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"destinationServiceName":\s{0,100}"({app}[^"]+)""",
    """"id":\s{0,100}"({alert_id}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"description":\s{0,100}"({additional_info}[^"]+?)\s{0,100}"""",
    """"category":\s{0,100}"({alert_name}[^"]+)""",
    """"title":\s{0,100}"({alert_name}[^"]+?)\s{0,100}"""",
    """"category":\s{0,100}"({alert_type}[^"]+)""",
    """"status":\s{0,100}"(unknown|({outcome}[^"]+))""",
    """"logonLocation":\s{0,100}"({location}[^"]+)""",
  ]
}
```