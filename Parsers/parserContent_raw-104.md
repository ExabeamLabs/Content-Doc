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
    """({host}\S+)\s+MSWinEventLog\s+\S+\s+\S+\s+\S+\s+\S+\s+({time}\w+ \d+ \d\d:\d\d:\d\d \d+)\s+({event_code}104)\s+Microsoft-Windows-Eventlog\s+(({domain}[^\\]+?)\\+)?({user}[^\s]+)"""
    """({event_name}The.*?log file was cleared.)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```