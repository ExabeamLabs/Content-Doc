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
    """\Wdvc="({host}[\w.\-]{1,2000})""",
    """\Wtimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wother_references="({additional_info}[^"]{1,2000})"""",
    """\Wdest="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^"]{1,2000}))"""",
    """\Wip="({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wseverity="({alert_severity}[^"]{1,2000})"""",
    """\Wsignature="({alert_name}[^"]{1,2000})"""",
    """\Wcategory="({alert_type}[^"]{1,2000})""""
  ]
  DupFields = [ "host->dest_host" ]
}
```