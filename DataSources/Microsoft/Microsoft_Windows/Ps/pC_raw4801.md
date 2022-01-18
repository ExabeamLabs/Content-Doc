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
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})""",
    """(?i)(((audit|success)( |_)(success|audit))|information)(<\d{1,100}>|\s{1,100})({host}[\w\-.]{1,2000})""",
    """({event_code}4801)""",
    """Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain""",
    """Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}Session""",
    """\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}([\+\-]\d{1,100}:\d{1,100}|Z)\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)"""
  ]
  DupFields = [ "host->dest_host" ]


}
```