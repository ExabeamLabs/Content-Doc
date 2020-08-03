#### Parser Content
```Java
{
Name = rsa-dlp-alert
  Vendor = RSA
  Product = RSA DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """DLP_EM:""", """usage=""", "usageApplication=" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """DLP_EM:\s*({host}[^\s]+)""",
    """User=(({domain}[^\\]+)\\)?({user}.+?)\s+\w+=""",
    """Incident\s*:*\s*"({alert_name}[^"]+)""",
    """Severity=({alert_severity}[^\s]+)""",
    """Policy=({alert_type}.+?)\s+\w+=""",
    """userEmail=({user_email}[^\s]+)""",
    """action=({outcome}.+?)\s+\w+=""",
    """usage=({alert_type}.+?)\s+\w+=""",
    """usageIp=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """usageApplication=({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+\w+="""
  ]
  DupFields = ["directory->process_directory"]
}
```