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
    """\s{1,100}({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):.+?/Security\s{1,100}\(({event_code}\d{1,100})\)""",
    """Successful Logon:\s{1,100}User Name:\s{1,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}[\w.\-]+)\s{1,100}Logon ID:\s{1,100}\([^,]+,({logon_id}[^\)]+)""",
    """Logon Type:\s{1,100}({logon_type}[\d]+)""",
    """Logon Process:\s{1,100}({auth_process}.+?)\s{1,100}Authentication Package:\s{1,100}({auth_package}[^\s]+)""",
    """Workstation Name:\s{1,100}({src_host_windows}[\w.\-\$]+)""",
    """Workstation Name:\s{1,100}({src_host}[\w.\-\$]+).*?Source Network Address:\s{0,100}-\s{1,100}""",
    """Workstation Name:\s{1,100}({dest_host}[\w.\-\$]+)""",
    """Caller User Name:\s{1,100}({account}[\w.\-\$]+)""",
    """Source Network Address:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = [ "dest_host->host"]
}
```