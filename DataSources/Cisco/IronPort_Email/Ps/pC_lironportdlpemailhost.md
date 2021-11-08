#### Parser Content
```Java
{
Name = l-ironport-dlp-email-host
  Vendor = Cisco
  Product = IronPort Email
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ MID """, """Hostname=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Hostname=({src_host}[\w.-]{1,2000})"""
  ]
}
```