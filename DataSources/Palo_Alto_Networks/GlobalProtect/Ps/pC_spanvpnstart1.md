#### Parser Content
```Java
{
Name = s-pan-vpn-start-1
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """globalprotect""", "user authentication succeeded", "-auth-succ" ]
  Fields = [
    """User name:\s{1,100}(({domain}[^,"\\\/]{1,2000})[\\\/]{1,2000})?(({user_email}({user_fullname}[^,]{1,2000})@({email_domain}[^,]{1,2000}))|({user}[^,"]{1,2000}))[,"]""",
    """Login from:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """DeviceName =({host}[\w\-.]{1,2000})""",
    """globalprotect\w*-\S+?,({host}.+?),""",
    """:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
    """SYSTEM,({vpn_client}[^,]{1,2000}),""",
    """Source region:\s{0,100}({src_country}[^,]{1,2000})?""",
  ]


}
```