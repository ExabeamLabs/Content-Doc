#### Parser Content
```Java
{
Name = raw-1102
  Lms = Splunk
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "1102", "The audit log was cleared", "MSWinEventLog" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+({time}\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\d\d\d\d)\s+""",
  ]
}
```