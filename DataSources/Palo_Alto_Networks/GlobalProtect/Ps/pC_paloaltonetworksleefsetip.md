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
    """DeviceName=({host}[^\s"]{1,2000})"""
    """Private IP:\s{0,100}({src_translated_ip}[a-fA-F\d.:]{1,2000}[^\."])""",
    """User name:\s{1,100}({user}[^,\s@]{1,2000})""",
    """Severity=({severity}[^\s|]{1,2000})""",
    """cat=({category}[^\s|]{1,2000})""",
    """Client OS ( version)?.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}
```