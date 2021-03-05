#### Parser Content
```Java
{
Name = raw-pan-vpn-set-ip
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotect,""", "client configuration generated" ]
  Fields = [
    """({time}\d\d\d\d/\d\d/\d\d \d+:\d+:\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """globalprotect(gateway|portal)-\S+?,({host}.+?),""",
    """Private IP:\s?({src_translated_ip}[^,\s]+)""",
    """User name:\s+({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s+({os}[^":]+)(,|\.)""",
    """SYSTEM,({vpn_client}[^,]+),""",
    """Source region:\s*({src_country}[^,]+)"""
  ]
}
```