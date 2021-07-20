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
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF:""",
    """\|SIEM Notification\|(?:[^\|]{1,2000}\|){10}\s{1,100}((NT AUTHORITY|({domain}[^\/\s]{1,2000}))\/)?(SYSTEM|({user}[^\s\|]{1,2000}))\s{1,100}\|""",
    """SIEM Notification\|(?:[^\|]{1,2000}\|){7}\s{1,100}([^\\]{0,2000}\\)?({src_host}[^\s\|\$]{1,2000})\$?\s{0,100}""",
    """SIEM Notification\|(?:[^\|]{1,2000}\|){3}\s{1,100}({alert_name}[^\|]{1,2000})\s{1,100}\|""",
    """SIEM Notification\|(?:[^\|]{1,2000}\|){4}\s{1,100}({alert_type}[^\|]{1,2000})\s{1,100}\|""",
    """SIEM Notification\|(?:[^\|]{1,2000}\|){6}\s{1,100}({target}[^\|]{1,2000})\s{1,100}\|"""
  ]
}
```