#### Parser Content
```Java
{
Name = r-syslog-bluecoatcas-alert
  Vendor = Symantec
  Product = Symantec Blue Coat Content Analysis System
  Lms = Direct
  DataType = "alert"
  TimeFormat =  "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """avservice[""", """Antivirus Vendor:""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """Timestamp: ({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """avservice\[({alert_id}\d{1,100})\]\s{1,100}({alert_name}[^,]{1,2000})""",
    """avservice\[\d{1,100}\]\s{1,100}({alert_type}[^,]{1,2000})""",
    """Client: (({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,\s]{1,2000}))""",
    """URL: ({malware_url}[^,]{1,2000})"""
  ]
}
```