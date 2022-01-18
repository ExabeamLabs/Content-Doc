#### Parser Content
```Java
{
Name = raw-pan-vpn-end
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """globalprotect""", "user logout succeeded", "-logout-succ" ]
  Fields = [
    """({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """User name:\s{0,100}({user}[\w.'\-\\$]{1,2000})""",
    """User name:\s{0,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """DeviceName =({host}[\w\-.]{1,2000})""",
    """globalprotectgateway-\S+?,({host}.+?),""",
    """SYSTEM,({vpn_client}[^,]{1,2000}),""",
    """\WReason:\s{0,100}({reason}[^",]{1,2000}?)\.?(\s{1,100}\w+=|[",]|\s{0,100}$)"""
  ]


}
```