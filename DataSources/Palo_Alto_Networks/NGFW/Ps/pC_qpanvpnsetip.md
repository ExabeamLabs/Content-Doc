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
    """User name:\s{1,100}({user}[\w.'\-\\$]{1,2000}?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """\|devTime=({time}\w{3}\s{1,100}\d{1,100} \d\d\d\d \d\d:\d\d:\d\d \w+)\|""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """DeviceName=({host}[\w\-.]{1,2000})""",
    """Client OS( version)?:\s{1,100}({os}[^":]{1,2000})(,|\.)""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})"""
  ]

```