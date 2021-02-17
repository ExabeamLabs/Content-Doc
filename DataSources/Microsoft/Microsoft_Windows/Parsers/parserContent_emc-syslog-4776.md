#### Parser Content
```Java
{
Name = emc-syslog-4776
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "attempted to validate the credentials for an account","""eventid="4776""""]
  Fields = [
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """Source Workstation:\s*(\\+)?(({dest_ip}[A-Fa-f:\d.]+)|(?:(?!NULL)({dest_host}[^\s]+)))?(:\d+)?\s*Error Code:""",
    """({event_code}4776)""",
    """Logon (?:a|A)ccount:\s+({user}[^@]+?)(?:@({domain}[^\s.]+)[^\s]*)?\s+Source Workstation""",
    """Error Code:\s+({result_code}[\w\-]+)""",
     ]
}
```