#### Parser Content
```Java
{
Name = xml-1102
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["The audit log was cleared", "<EventID>1102" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)"""
    """\s+Logon ID:\s+({logon_id}[^<]+)"""
  ]
}
```