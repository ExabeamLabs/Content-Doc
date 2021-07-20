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
    """\|dvchost=({host}[^\|]{1,2000})""",
    """\sDamballa\|Failsafe\|[^\|]{1,2000}\|({alert_name}[^\|]{1,2000})""",
    """\|cs2=({alert_name}[^\|]{1,2000})""",
    """\|cfp1=({alert_severity}[^\|]{1,2000})""",
    """\|cs7=({alert_type}[^\|]{1,2000})""",
    """\|destinationDnsDomain=({malware_url}[^\|]{1,2000})""",
    """\|dst=({dest_ip}[^\|]{1,2000})""",
    """\|externalId=({alert_id}[^\|]{1,2000})""",
    """\|shost=({src_host}[^\|]{1,2000})""",
    """\|src=({src_ip}[^\|]{1,2000})"""
  ]
}
```