#### Parser Content
```Java
{
Name = evntslog-528
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-528"
  TimeFormat = "E MMM dd HH:mm:ss yyyy"
  Conditions = [ "EvntSLog", "(528)" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """\s+({time}\w+ \w+ \d+ \d+:\d+:\d+ \d+):.+?/Security\s+\(({event_code}\d+)\)""",
    """Successful Logon:\s+User Name:\s+({user}.+?)\s+Domain:\s+({domain}[\w.\-]+)\s+Logon ID:\s+\([^,]+,({logon_id}[^\)]+)""",
    """Logon Type:\s+({logon_type}[\d]+)""",
    """Logon Process:\s+({auth_process}.+?)\s+Authentication Package:\s+({auth_package}[^\s]+)""",
    """Workstation Name:\s+({src_host_windows}[\w.\-\$]+)""",
    """Workstation Name:\s+({src_host}[\w.\-\$]+).*?Source Network Address:\s*-\s+""",
    """Workstation Name:\s+({dest_host}[\w.\-\$]+)""",
    """Caller User Name:\s+({account}[\w.\-\$]+)""",
    """Source Network Address:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = [ "dest_host->host"]
}
```