#### Parser Content
```Java
{
Name = s-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-680"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ "EventCode=680" ]
  Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """({event_name}Logon attempt)""",
             """EventCode=({event_code}\w+)""",
             """Logon account:\s+({user}[^@]+?)(?:@({domain}[^\s.]+)[^\s]*)?\s+Source Workstation:\s+({dest_host}[^\s]+)""",
             """Error Code:\s+({result_code}[\w\-]+)""",
             """Sid=({user_sid}[^\s]+)\s+SidType""",
             """ComputerName=[^.\s]+(\.({domain}[^.\s]+))?"""
  ]
}
```