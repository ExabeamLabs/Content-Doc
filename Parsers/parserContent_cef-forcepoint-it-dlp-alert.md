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
    """\|SIEM Notification\|(?:[^\|]+\|){10}\s+((NT AUTHORITY|({domain}[^\/\s]+))\/)?(SYSTEM|({user}[^\s\|]+))\s+\|""",
    """SIEM Notification\|(?:[^\|]+\|){7}\s+([^\\]*\\)?({src_host}[^\s\|\$]+)\$?\s*""",
    """SIEM Notification\|(?:[^\|]+\|){3}\s+({alert_name}[^\|]+)\s+\|""",
    """SIEM Notification\|(?:[^\|]+\|){4}\s+({alert_type}[^\|]+)\s+\|""",
    """SIEM Notification\|(?:[^\|]+\|){6}\s+({target}[^\|]+)\s+\|"""
  ]
}
```