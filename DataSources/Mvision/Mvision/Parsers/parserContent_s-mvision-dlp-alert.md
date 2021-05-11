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
    """<\d{1,100}>\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """\WupdatedOn="({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\WpolicyName="({alert_name}[^"]+)""",
    """\WincidentId=({alert_id}\d{1,100})""",
    """\WriskSeverity=({alert_severity}[^,]+)""",
    """\WactivityName=\[({alert_type}[^\[\]]+?)\]""",
    """\WsourceIps=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))""",
    """\WactorId=({user_email}[^,]+)""",
    """\WFileSize=({bytes}\d{1,100})""",
    """\WcontentItemId="({target}[^"]+)""",
    """\WcontentItemName="({file_name}[^"]+)""",
    """\WinstanceName="({src_host}[^"]+)""",
    """\Wresponse=\[({outcome}[^\[\]]+?)\]""",
    """\W({additional_info}totalMatchCount=[^,]+)""",
  ]
}
```