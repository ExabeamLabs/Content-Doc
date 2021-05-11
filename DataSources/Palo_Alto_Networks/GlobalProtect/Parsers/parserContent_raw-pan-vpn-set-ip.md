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
    """({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """globalprotect(gateway|portal)-\S+?,({host}[^,]+),""",
    """Private IP:\s?({src_translated_ip}[^,\s]+)""",
    """User name:\s{1,100}({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s{1,100}({os}[^":]+)(,|\.)""",
    """SYSTEM,({vpn_client}[^,]+),""",
    """Source region:\s{0,100}({src_country}[^,]+)""",
    """Device name:\s({src_host}[^,]+)"""
  ]
}
```