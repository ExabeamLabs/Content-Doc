#### Parser Content
```Java
{
Name = s-codegreen-dlp-alert
  Vendor = Code Green Network (Digital Guardian)
  Product = TrueDLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """matched_policies_by_severity=""", """email_subject=""", "exabeam_raw" ]
  Fields = [
    """timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \w+)"""",
    """\d\d:\d\d ({host}[^\s]+)\s+\d+\s+\d{4}\-""",
    """source="(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^"\\;]+))"""",
    """destination="(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({target}[^"]+))"""",
    """inspected_document="(?:|({additional_info}.+?))"""",
    """protocol="({alert_type}[^"]+)""",
    """protocol="({protocol}[^"]+)""",
    """protocol="FTP"\s+inspected_document="({file_name}[^"]+)""",
    """action_taken="({outcome}[^"]+)""",
    """source_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """destination_ip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """matched_policies_by_severity="*({alert_severity}[^"]+)""",
    """matched_policies_by_severity="\w+:({alert_name}[^,;\/]+)"""
  ]
}
```