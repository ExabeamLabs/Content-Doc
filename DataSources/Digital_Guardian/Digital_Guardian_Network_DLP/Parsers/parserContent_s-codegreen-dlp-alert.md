#### Parser Content
```Java
{
Name = s-codegreen-dlp-alert
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """matched_policies_by_severity=""", """email_subject=""", "exabeam_raw" ]
  Fields = [
    """timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \w+)"""",
    """\d\d:\d\d ({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}\d{4}\-""",
    """source="(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^"\\;]{1,2000}))"""",
    """destination="(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({target}[^"]{1,2000}))"""",
    """inspected_document="(?:|({additional_info}.+?))"""",
    """protocol="({alert_type}[^"]{1,2000})""",
    """protocol="({protocol}[^"]{1,2000})""",
    """protocol="FTP"\s{1,100}inspected_document="({file_name}[^"]{1,2000})""",
    """action_taken="({outcome}[^"]{1,2000})""",
    """source_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """destination_ip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """matched_policies_by_severity="{0,20}({alert_severity}[^"]{1,2000})""",
    """matched_policies_by_severity="\w+:({alert_name}[^,;\/]{1,2000})"""
  ]
}
```