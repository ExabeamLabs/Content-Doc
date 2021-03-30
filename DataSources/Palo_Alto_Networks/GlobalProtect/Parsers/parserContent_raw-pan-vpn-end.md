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
    """({time}\d\d\d\d/\d\d/\d\d \d+:\d+:\d+)""",
    """User name:\s*({user}[\w.'\-\\$]+)""",
    """User name:\s*({user_email}[^@\s]+@[^\s,]+),""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """DeviceName=({host}[\w\-.]+)""",
    """globalprotectgateway-\S+?,({host}.+?),""",
    """SYSTEM,({vpn_client}[^,]+),""",
    """\WReason:\s*({reason}[^",]+?)\.?(\s+\w+=|[",]|\s*$)"""
  ]
}
```