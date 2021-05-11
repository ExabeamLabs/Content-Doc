#### Parser Content
```Java
{
Name = cef-forcepoint-it-dlp-alert
  Vendor = Forcepoint
  Product = Forcepoint Insider Threat
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|SIEM Notification|"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF:""",
    """\|SIEM Notification\|(?:[^\|]+\|){10}\s{1,100}((NT AUTHORITY|({domain}[^\/\s]+))\/)?(SYSTEM|({user}[^\s\|]+))\s{1,100}\|""",
    """SIEM Notification\|(?:[^\|]+\|){7}\s{1,100}([^\\]*\\)?({src_host}[^\s\|\$]+)\$?\s{0,100}""",
    """SIEM Notification\|(?:[^\|]+\|){3}\s{1,100}({alert_name}[^\|]+)\s{1,100}\|""",
    """SIEM Notification\|(?:[^\|]+\|){4}\s{1,100}({alert_type}[^\|]+)\s{1,100}\|""",
    """SIEM Notification\|(?:[^\|]+\|){6}\s{1,100}({target}[^\|]+)\s{1,100}\|"""
  ]
}
```