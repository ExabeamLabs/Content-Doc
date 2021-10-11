#### Parser Content
```Java
{
Name = r-nic-540
  Vendor = Microsoft
  Product = Windows
  Lms = RsaSa
  DataType = "windows-540"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", "Successful Network Logon:", ",540,", "Security", "Success Audit", "rsa_sa_log" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}),""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """\d{2}:\d{2}:\d{2} \d{4},({event_code}[^,]{1,2000}),Security""",
    """Security,({record_id}\d{1,100})""",
    """User Name:\s{1,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}\([^,\s]{1,2000}[,\s]({logon_id}[^\)]{1,2000})\)\s{1,100}Logon Type:\s{1,100}({logon_type}\d{1,100})\s{1,100}Logon Process:\s{1,100}({process}.+?)\s{1,100}Authentication Package""",
    """Logon Process:\s{1,100}({auth_process}.+?)\s{1,100}Authentication Package:\s{1,100}({auth_package}[^\s]{1,2000})""",
    """Workstation Name:\s{1,100}({src_host_windows}[^\s]{1,2000})\s{1,100}Logon""",
    """Workstation Name:\s{1,100}({src_host}[^\s]{1,2000})\s{1,100}Logon.*?Source Network Address:\s{0,100}-\s{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]
}
```