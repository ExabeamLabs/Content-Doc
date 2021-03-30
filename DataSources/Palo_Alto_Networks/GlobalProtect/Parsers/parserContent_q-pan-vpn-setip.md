#### Parser Content
```Java
{
Name = q-pan-vpn-setip
  DataType = "vpn-set-ip"
  Conditions = [ "subtype=globalprotect","globalprotect","Palo Alto Networks", "client configuration generated" ]
  Fields = ${PAParserTemplates.q-pan-vpn-parser.Fields} [
    """Private IP:\s?({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
q-pan-vpn-parser = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = QRadar
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Fields = [
    """User name:\s+({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """\|devTime=({time}\w{3}\s+\d+ \d\d\d\d \d\d:\d\d:\d\d \w+)\|""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """DeviceName=({host}[\w\-.]+)""",
    """Client OS( version)?:\s+({os}[^":]+)(,|\.)""",
    """Login from:\s*({src_ip}[a-fA-F\d.:]+)"""
  ]

```