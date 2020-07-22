#### Parser Content
```Java
{
Name = raw-4800
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4800"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "The workstation was locked", "4800" ]
  Fields = [
    """({event_name}The workstation was locked)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
    """(?i)(((audit|success)( |_)(success|audit))|information)(<\d+>|\s+)({host}[\w\-.]+)""",
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s+({host}[\w.\-]+)""",
    """({event_code}4800)""",
    """Account Name:\s*({user}.+?)\s*Account Domain""",
    """Account Domain:\s*({domain}.+?)\s*Logon ID""",
    """Logon ID:\s*({logon_id}[^\s]+)\s+Session"""
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```