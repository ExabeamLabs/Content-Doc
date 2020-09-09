#### Parser Content
```Java
{
Name = raw-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-540"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Logon Type:", "Successful Network Logon:" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """\s(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+540\s+Security""",
    """exabeam_host=({host}[\w.\-]+)""",
    """(?i)(((audit|success)( |_)(success|audit))|information)\s*,?\s*({host}[\w\-.]+)""",
    """({host}[^\/\s]+)\/Security\s+\(""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
    """({event_code}540)""",
    """User Name\s*:\s*(-|<null>|({user}[^\s]+))\s+Domain\s*:\s*(-|({domain}[^\s]+))\s""",
    """({user}ANONYMOUS LOGON)""",
    """Source Network Address\s*:\s*(?:-|({src_ip}[\w:.]+))\s+Source Port:""",
    """Workstation Name\s*:\s*(-|({src_host_windows}[^\s]+))\s+Logon GUID:""",
    """Workstation Name\s*:\s*({src_host}[^\s]+)\s+Logon GUID:.*?Source Network Address:\s*-\s+""",
    """Logon Process\s*:\s*({auth_process}.+?)\s+Authentication Package\s*:\s*({auth_package}.+?)\s+Workstation Name:""",
    """Logon ID\s*:\s*[^,\s]+[,\s]({logon_id}[^\)]+)\)\s+Logon Type\s*:\s*({logon_type}\d+)""",
    """Security(\s+|,)(rn=)?({record_id}\d+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```