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
    """Information\s+({host}[\w.\-]+)\s+""",
    """(?:Success|Audit)\s+\w+\s+({host}[^\s]+)""",
    """Security\s+(rn=)?({record_id}\d+)""",
    """User Name:\s+({user}.+?)\s+Domain:\s+({domain}.+?)\s+Logon ID:\s+\([^,\s]+[,\s]({logon_id}[^\)]+)\)\s+Logon Type:\s+({logon_type}\d+)\s+Logon Process:""",
    """Logon Process:\s+({auth_process}.+?)\s+Authentication Package:\s+({auth_package}[^\s]+)""",
    """Source Network Address:\s+({src_ip}[a-fA-F:\d.]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```