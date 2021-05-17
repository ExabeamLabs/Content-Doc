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
    """protocol=Endpoint\s({protocol}[^,]{0,2000}),""",
    """dest_host=({target}.*?),incident""",
    """src_host=({src_host}[^,]{0,2000}),subject""",
    """user=[^@]{0,2000}@({domain}[^,]{1,2000})""",
    """event_id=({alert_id}\d{6})""",
    """signature=({alert_name}[^,]{0,2000})""",
    """subject=({additional_info}[^,]{0,2000})""",
    """protocol=({alert_type}[^,]{0,2000}),""",
    """user=({user_email}[^,]{1,2000}),"""
  ]
}
```