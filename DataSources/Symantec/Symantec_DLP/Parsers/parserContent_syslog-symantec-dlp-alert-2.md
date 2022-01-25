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
    """exabeam_\w+=\s{0,100}({host}[\w\-\.]{1,2000})\s{1,100}({alert_id}\d{1,100})\s{1,100}({src_host}[\w\-\.]{1,2000})\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(({domain}[^\\\s]{1,2000})\\)?({user}[^\s]{1,2000})\s{1,100}\S+\s{1,100}({time}\w+ \d\d, \d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (PM|pm|AM|am))\s{1,100}""",
    """({alert_name}Endpoint-Insider Threat  ITP - Monitor C&P printing)""",
    """,\s{1,100}({file_name}[^,]{1,2000}?)\s{1,100}On the Corporate Network""",
    """,\s{1,100}.*N\/A\s{1,100}({file_name}[^,]{1,2000}?)\s{1,100}On the Corporate Network"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```