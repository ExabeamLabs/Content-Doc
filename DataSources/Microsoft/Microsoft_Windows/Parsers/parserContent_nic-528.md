#### Parser Content
```Java
{
Name = nic-528
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-528"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", " 528 Security", "Successful Logon:" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """({event_code}528)""",
    """Information\s{1,100}({host}[\w.\-]+)\s{1,100}""",
    """(?:Success|Audit)\s{1,100}\w+\s{1,100}({host}[^\s]+)""",
    """Security\s{1,100}(rn=)?({record_id}\d{1,100})""",
    """User Name:\s{1,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}\([^,\s]+[,\s]({logon_id}[^\)]+)\)\s{1,100}Logon Type:\s{1,100}({logon_type}\d{1,100})\s{1,100}Logon Process:""",
    """Logon Process:\s{1,100}({auth_process}.+?)\s{1,100}Authentication Package:\s{1,100}({auth_package}[^\s]+)""",
    """Source Network Address:\s{1,100}({src_ip}[a-fA-F:\d.]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```