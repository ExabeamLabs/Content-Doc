#### Parser Content
```Java
{
Name = raw-540
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-540"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Logon Type:", "Successful Network Logon:" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """\s(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}540\s{1,100}Security""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100},?\s{0,100}({host}[\w\-.]{1,2000})""",
    """({host}[^\/\s]{1,2000})\/Security\s{1,100}\(""",
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
    """({event_code}540)""",
    """User Name\s{0,100}:\s{0,100}(-|<null>|({user}[^\s]{1,2000}))\s{1,100}Domain\s{0,100}:\s{0,100}(-|({domain}[^\s]{1,2000}))\s""",
    """Source Network Address\s{0,100}:\s{0,100}(?:-|({src_ip}[\w:.]{1,2000}))\s{1,100}Source Port:""",
    """Workstation Name\s{0,100}:\s{0,100}(-|({src_host_windows}[^\s]{1,2000}))\s{1,100}Logon GUID:""",
    """Workstation Name\s{0,100}:\s{0,100}({src_host}[^\s]{1,2000})\s{1,100}Logon GUID:.*?Source Network Address:\s{0,100}-\s{1,100}""",
    """Logon Process\s{0,100}:\s{0,100}({auth_process}.+?)\s{1,100}Authentication Package\s{0,100}:\s{0,100}({auth_package}.+?)\s{1,100}Workstation Name:""",
    """Logon ID\s{0,100}:\s{0,100}[^,\s]{1,2000}[,\s]({logon_id}[^\)]{1,2000})\)\s{1,100}Logon Type\s{0,100}:\s{0,100}({logon_type}\d{1,100})""",
    """Security(\s{1,100}|,)(rn=)?({record_id}\d{1,100})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```