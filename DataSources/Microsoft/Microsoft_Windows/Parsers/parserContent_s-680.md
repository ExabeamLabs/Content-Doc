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
  Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """({event_name}Logon attempt)""",
             """EventCode=({event_code}\w+)""",
             """Logon account:\s{1,100}({user}[^@]+?)(?:@({domain}[^\s.]+)[^\s]*)?\s{1,100}Source Workstation:\s{1,100}({dest_host}[^\s]+)""",
             """Error Code:\s{1,100}({result_code}[\w\-]+)""",
             """Sid=({user_sid}[^\s]+)\s{1,100}SidType""",
             """ComputerName=[^.\s]+(\.({domain}[^.\s]+))?"""
  ]
}
```