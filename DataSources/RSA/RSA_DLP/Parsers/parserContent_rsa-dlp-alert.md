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
    """DLP_EM:\s{0,100}({host}[^\s]+)""",
    """User=(({domain}[^\\]+)\\)?({user}.+?)\s{1,100}\w+=""",
    """Incident\s{0,100}:*\s{0,100}"({alert_name}[^"]+)""",
    """Severity=({alert_severity}[^\s]+)""",
    """Policy=({alert_type}.+?)\s{1,100}\w+=""",
    """userEmail=({user_email}[^\s]+)""",
    """action=({outcome}.+?)\s{1,100}\w+=""",
    """usage=({alert_type}.+?)\s{1,100}\w+=""",
    """usageIp=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """usageApplication=({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s{1,100}\w+="""
  ]
  DupFields = ["directory->process_directory"]
}
```