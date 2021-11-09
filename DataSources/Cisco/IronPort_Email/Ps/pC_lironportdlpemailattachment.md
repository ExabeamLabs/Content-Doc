#### Parser Content
```Java
{
Name = l-ironport-dlp-email-attachment
  Vendor = Cisco
  Product = IronPort Email
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ MID """, """FileTypes=""", """FileNames=""", """FileSizes=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """FileTypes=({file_type}[^=]{1,2000}),\s\w+=""",
    """FileNames=({attachment}[^=]{1,2000}?),\s\w+=""",
    """FileSizes=({bytes}\d{1,100})""",
    """MID ({alert_id}\d{1,100})"""
  ]
}
}
```