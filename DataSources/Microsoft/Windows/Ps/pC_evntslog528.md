#### Parser Content
```Java
{
Name = evntslog-528
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "windows-528"
  TimeFormat = "E MMM dd HH:mm:ss yyyy"
  Conditions = [ "EvntSLog", "(528)" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """\s{1,100}({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):.+?/Security\s{1,100}\(({event_code}\d{1,100})\)""",
    """Successful Logon:\s{1,100}User Name:\s{1,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}[\w.\-]{1,2000})\s{1,100}Logon ID:\s{1,100}\([^,]{1,2000},({logon_id}[^\)]{1,2000})""",
    """Logon Type:\s{1,100}({logon_type}[\d]{1,2000})""",
    """Logon Process:\s{1,100}({auth_process}.+?)\s{1,100}Authentication Package:\s{1,100}({auth_package}[^\s]{1,2000})""",
    """Workstation Name:\s{1,100}({src_host_windows}[\w.\-\$]{1,2000})""",
    """Workstation Name:\s{1,100}({src_host}[\w.\-\$]{1,2000}).*?Source Network Address:\s{0,100}-\s{1,100}""",
    """Workstation Name:\s{1,100}({dest_host}[\w.\-\$]{1,2000})""",
    """Caller User Name:\s{1,100}({account}[\w.\-\$]{1,2000})""",
    """Source Network Address:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = [ "dest_host->host"]
}
```