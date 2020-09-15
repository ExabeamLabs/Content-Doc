#### Parser Content
```Java
{
Name = raw-pan-vpn-start
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotect,""", "user login succeeded" ]
  Fields = [
    """User name:\s+({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Login from:\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({time}\d\d\d\d/\d\d/\d\d \d+:\d+:\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """globalprotectgateway-\S+?,({host}.+?),""",
    """SYSTEM,({vpn_client}[^,]+),""",
    """Source region:\s*({src_country}[^,]+)"""
  ]
}
```