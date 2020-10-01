#### Parser Content
```Java
{
Name = raw-528
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-528"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Logon Type:", "Successful Logon:" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """\s(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+528\s+Security\s""",
    """exabeam_host=({host}[\w.\-]+)""",
    """(?i)(((audit|success)( |_)(success|audit))|information)\s*,?\s*({host}[\w\-.]+)""",
    """"dhn":"({host}[^-"]+)""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
    """({event_code}528)""",
    """User Name\s*:\s*({user}.+?)\s+Domain:\s+({domain}[^\s]+)""",
    """Source Network Address\s*:\s*(?:-|({src_ip}[\w:.]+))\s+Source Port:""",
    """Workstation Name\s*:\s*({src_host_windows}[^\s]+)\s*""",
    """Workstation Name\s*:\s*({src_host}[^\s]+).*?Source Network Address:\s*-\s+""",
    """Logon Process\s*:\s*({auth_process}.+?)\s+Authentication Package\s*:\s*({auth_package}[^\s]+)""",
    """Logon ID\s*:\s*[^,\s]+[,\s]({logon_id}[^\)]+)\)\s+Logon Type\s*:\s*({logon_type}\d+)""",
    """Security,({record_id}\d+)""",
    """\sSecurity.+?({record_id}\d+)\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s""",
    """Sid=({user_sid}[^\s]+)\s+SidType"""
  ]
  DupFields = [ "host->dest_host" ]
}
```