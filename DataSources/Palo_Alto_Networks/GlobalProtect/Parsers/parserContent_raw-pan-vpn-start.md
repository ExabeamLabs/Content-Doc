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
    """User name:\s{1,100}({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]+@[^\s,]+),""",
    """Login from:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """globalprotectgateway-\S+?,({host}.+?),""",
    """SYSTEM,({vpn_client}[^,]+),""",
    """Source region:\s{0,100}({src_country}[^,]+)"""
  ]
}
```