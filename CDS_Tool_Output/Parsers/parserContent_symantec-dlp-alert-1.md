#### Parser Content
```Java
{
Name = symantec-dlp-alert-1
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""protocol=Endpoint""","""signature="""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,severity=({alert_severity}\d{1})""",
    """protocol=Endpoint\s({protocol}[^,]*),""",
    """dest_host=({target}.*?),incident""",
    """src_host=({src_host}[^,]*),subject""",
    """user=[^@]*@({domain}[^,]+)""",
    """event_id=({alert_id}\d{6})""",
    """signature=({alert_name}[^,]*)""",
    """subject=({additional_info}[^,]*)""",
    """protocol=({alert_type}[^,]*),""",
    """user=({user_email}[^,]+),"""
  ]
}
```