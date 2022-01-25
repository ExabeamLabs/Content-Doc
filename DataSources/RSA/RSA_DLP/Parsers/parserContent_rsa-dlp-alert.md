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
    """DLP_EM:\s{0,100}({host}[^\s]{1,2000})""",
    """User=(({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}\w+=""",
    """Incident\s{0,100}:*\s{0,100}"({alert_name}[^"]{1,2000})""",
    """Severity=({alert_severity}[^\s]{1,2000})""",
    """Policy=({alert_type}.+?)\s{1,100}\w+=""",
    """userEmail=({user_email}[^\s]{1,2000})""",
    """action=({outcome}.+?)\s{1,100}\w+=""",
    """usage=({alert_type}.+?)\s{1,100}\w+=""",
    """usageIp=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """usageApplication=({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}\w+="""
  ]
  DupFields = ["directory->process_directory"]
}
```