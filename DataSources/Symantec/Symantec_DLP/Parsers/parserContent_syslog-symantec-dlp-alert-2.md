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
    """exabeam_\w+=\s{0,100}({host}[\w\-\.]+)\s{1,100}({alert_id}\d{1,100})\s{1,100}({src_host}[\w\-\.]+)\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(({domain}[^\\\s]+)\\)?({user}[^\s]+)\s{1,100}\S+\s{1,100}({time}\w+ \d\d, \d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (PM|pm|AM|am))\s{1,100}""",
    """({alert_name}Endpoint-Insider Threat  ITP - Monitor C&P printing)""",
    """,\s{1,100}({file_name}[^,]+?)\s{1,100}On the Corporate Network""",
    """,\s{1,100}.*N\/A\s{1,100}({file_name}[^,]+?)\s{1,100}On the Corporate Network"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```