#### Parser Content
```Java
{
Name = palo-alto-networks-leef-setip
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """LEEF:""", """Private IP:""", """User name:""", """globalprotect""", """Device name:"""] 
  Fields = [
    """\|ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """DeviceName=({host}[^\s"]+)"""
    """Private IP:\s*({src_translated_ip}[a-fA-F\d.:]+[^\."])""",
    """User name:\s+({user}[^,\s@]+)""",
    """Severity=({severity}[^\s|]+)""",
    """cat=({category}[^\s|]+)""",
    """Client OS ( version)?.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}
```