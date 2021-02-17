#### Parser Content
```Java
{
Name = s-damballa-alert
  Vendor = Damballa
  Product = Failsafe
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Damballa|Failsafe|""", """message:"""  ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\|dvchost=({host}[^\|]+)""",
    """\sDamballa\|Failsafe\|[^\|]+\|({alert_name}[^\|]+)""",
    """\|cs2=({alert_name}[^\|]+)""",
    """\|cfp1=({alert_severity}[^\|]+)""",
    """\|cs7=({alert_type}[^\|]+)""",
    """\|destinationDnsDomain=({malware_url}[^\|]+)""",
    """\|dst=({dest_ip}[^\|]+)""",
    """\|externalId=({alert_id}[^\|]+)""",
    """\|shost=({src_host}[^\|]+)""",
    """\|src=({src_ip}[^\|]+)"""
  ]
}
```