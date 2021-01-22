#### Parser Content
```Java
{
Name = s-1102
  Lms = Splunk
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=1102""", "The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\sComputerName=({host}[\w.\-]+)""",
    """({time}\d\d/\d\d/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))\s+"""
  ]
}
```