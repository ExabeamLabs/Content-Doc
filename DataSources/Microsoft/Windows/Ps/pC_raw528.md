#### Parser Content
```Java
{
Name = raw-528
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-528"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Logon Type:", "Successful Logon:" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """\s(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}528\s{1,100}Security\s""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100},?\s{0,100}({host}[\w\-.]{1,2000})""",
    """"dhn":"({host}[^-"]{1,2000})""",
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
    """({event_code}528)""",
    """User Name\s{0,100}:\s{0,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """Source Network Address\s{0,100}:\s{0,100}(?:-|({src_ip}[\w:.]{1,2000}))\s{1,100}Source Port:""",
    """Workstation Name\s{0,100}:\s{0,100}({src_host_windows}[^\s]{1,2000})\s{0,100}""",
    """Workstation Name\s{0,100}:\s{0,100}({src_host}[^\s]{1,2000}).*?Source Network Address:\s{0,100}-\s{1,100}""",
    """Logon Process\s{0,100}:\s{0,100}({auth_process}.+?)\s{1,100}Authentication Package\s{0,100}:\s{0,100}({auth_package}[^\s]{1,2000})""",
    """Logon ID\s{0,100}:\s{0,100}[^,\s]{1,2000}[,\s]({logon_id}[^\)]{1,2000})\)\s{1,100}Logon Type\s{0,100}:\s{0,100}({logon_type}\d{1,100})""",
    """Security,({record_id}\d{1,100})""",
    """\sSecurity.+?({record_id}\d{1,100})\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s""",
    """Sid=({user_sid}[^\s]{1,2000})\s{1,100}SidType"""
  ]
  DupFields = [ "host->dest_host" ]
}
```