#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-2
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Conditions = ["""Endpoint-Insider Threat  ITP - Monitor C&P printing"""]
  Fields = [
    """exabeam_\w+=\s*({host}[\w\-\.]+)\s+({alert_id}\d+)\s+({src_host}[\w\-\.]+)\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(({domain}[^\\\s]+)\\)?({user}[^\s]+)\s+\S+\s+({time}\w+ \d\d, \d\d\d\d \d+:\d+:\d+ (PM|pm|AM|am))\s+""",
    """({alert_name}Endpoint-Insider Threat  ITP - Monitor C&P printing)""",
    """,\s+({file_name}[^,]+?)\s+On the Corporate Network""",
    """,\s+.*N\/A\s+({file_name}[^,]+?)\s+On the Corporate Network"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```