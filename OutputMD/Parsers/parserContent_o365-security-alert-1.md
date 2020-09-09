#### Parser Content
```Java
{
Name = o365-security-alert-1
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"vendor": "Microsoft"""", """"riskScore":""", """"malwareStates":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"userPrincipalName":\s*"({user_email}[^"@]+@[^"]+)""",
    """"logonIp":\s*"({src_ip}[^"]+)""",
    """"userStates":\s*\[.*?accountName":\s*"({user}[^",]+)""",    
    """"accountName":\s*"({user}[^"]+)""",
    """"domainName":\s*"({domain}[^"]+)""",
    """"(eventDateTime|createdDateTime|lastModifiedDateTime)":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"destinationServiceName":\s*"({app}[^"]+)""",
    """"id":\s*"({alert_id}[^"]+)""",
    """"severity":\s*"({alert_severity}[^"]+)""",
    """"description":\s*"({additional_info}[^"]+?)\s*"""",
    """"category":\s*"({alert_name}[^"]+)""",
    """"title":\s*"({alert_name}[^"]+?)\s*"""",
    """"category":\s*"({alert_type}[^"]+)""",
    """"status":\s*"(unknown|({outcome}[^"]+))""",
    """"logonLocation":\s*"({location}[^"]+)""",
  ]
}
```