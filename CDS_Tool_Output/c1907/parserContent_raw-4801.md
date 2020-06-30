#### Parser Content
```Java
{
Name = raw-4801
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4801"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "The workstation was unlocked", "4801" ]
  Fields = [
    """({event_name}The workstation was unlocked)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
    """(?i)(((audit|success)( |_)(success|audit))|information)(<\d+>|\s+)({host}[\w\-.]+)""",
    """({event_code}4801)""",
    """Account Name:\s*({user}.+?)\s*Account Domain""",
    """Account Domain:\s*({domain}.+?)\s*Logon ID""",
    """Logon ID:\s+({logon_id}[^\s]+)\s+Session""",
    """\d+-\d+-\d+T\d+:\d+:\d+([\+\-]\d+:\d+|Z)\s+({host}[\w\-.]+)\s""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```