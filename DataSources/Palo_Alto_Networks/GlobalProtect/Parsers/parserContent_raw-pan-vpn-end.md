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
    """User name:\s{0,100}({user}[\w.'\-\\$]+)""",
    """User name:\s{0,100}({user_email}[^@\s]+@[^\s,]+),""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """DeviceName=({host}[\w\-.]+)""",
    """globalprotectgateway-\S+?,({host}.+?),""",
    """SYSTEM,({vpn_client}[^,]+),""",
    """\WReason:\s{0,100}({reason}[^",]+?)\.?(\s{1,100}\w+=|[",]|\s{0,100}$)"""
  ]
}
```