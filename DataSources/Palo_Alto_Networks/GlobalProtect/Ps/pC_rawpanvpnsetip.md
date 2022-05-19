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
    """globalprotect(gateway|portal)-\S+?,({host}[^,]{1,2000}),""",
    """:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
    """Private IP:\s?({src_translated_ip}[^,\s]{1,2000})""",
    """User name:\s{1,100}(({domain}[^,"\\\/]{1,2000})[\\\/]{1,2000})?(({user_email}[^,]{1,2000}@({email_domain}[^,]{1,2000}))|({user}[^,]{1,2000})),""",
    """Client OS( version)?:\s{1,100}({os}[^":]{1,2000})(,|\.)""",
    """SYSTEM,({vpn_client}[^,]{1,2000}),""",
    """Source region:\s{0,100}({src_country}[^,]{1,2000})""",
    """Device name:\s({src_host}[^,]{1,2000})"""
  ]


}
```