#### Parser Content
```Java
{
Name = raw-104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ 104 """, """Microsoft-Windows-Eventlog""", """log file was cleared.""" ]
  Fields = [
    """({host}\S+)\s{1,100}MSWinEventLog\s{1,100}\S+\s{1,100}\S+\s{1,100}\S+\s{1,100}\S+\s{1,100}({time}\w+ \d{1,100} \d\d:\d\d:\d\d \d{1,100})\s{1,100}({event_code}104)\s{1,100}Microsoft-Windows-Eventlog\s{1,100}(({domain}[^\\]{1,2000}?)\\+)?({user}[^\s]{1,2000})"""
    """({event_name}The.*?log file was cleared.)""",
  ]
  DupFields = [ "host->dest_host" ]


}
```