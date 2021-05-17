#### Parser Content
```Java
{
Name = s-mvision-dlp-alert
  Vendor = Mvision
  Product = Mvision
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions= [ """incidentGroup=Alert.Policy.Dlp""", """updatedOn="""" ]
  Fields = [
    """<\d{1,100}>\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """\WupdatedOn="({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\WpolicyName="({alert_name}[^"]{1,2000})""",
    """\WincidentId=({alert_id}\d{1,100})""",
    """\WriskSeverity=({alert_severity}[^,]{1,2000})""",
    """\WactivityName=\[({alert_type}[^\[\]]{1,2000}?)\]""",
    """\WsourceIps=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]{1,2000}))""",
    """\WactorId=({user_email}[^,]{1,2000})""",
    """\WFileSize=({bytes}\d{1,100})""",
    """\WcontentItemId="({target}[^"]{1,2000})""",
    """\WcontentItemName="({file_name}[^"]{1,2000})""",
    """\WinstanceName="({src_host}[^"]{1,2000})""",
    """\Wresponse=\[({outcome}[^\[\]]{1,2000}?)\]""",
    """\W({additional_info}totalMatchCount=[^,]{1,2000})""",
  ]
}
```