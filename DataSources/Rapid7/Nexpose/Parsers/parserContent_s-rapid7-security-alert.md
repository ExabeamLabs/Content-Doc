#### Parser Content
```Java
{
Name = s-rapid7-security-alert
  Vendor = Rapid7
  Product = Nexpose
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """, solution_summary="""", """, signature="""", """, severity="""" ]
  Fields = [
    """\Wdvc="({host}[\w.\-]+)""",
    """\Wtimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wother_references="({additional_info}[^"]+)"""",
    """\Wdest="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^"]+))"""",
    """\Wip="({src_ip}[a-fA-F\d.:]+)""",
    """\Wseverity="({alert_severity}[^"]+)"""",
    """\Wsignature="({alert_name}[^"]+)"""",
    """\Wcategory="({alert_type}[^"]+)""""
  ]
  DupFields = [ "host->dest_host" ]
}
```