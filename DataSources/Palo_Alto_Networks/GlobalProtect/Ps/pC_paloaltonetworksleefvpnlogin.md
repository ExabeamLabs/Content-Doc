#### Parser Content
```Java
{
Name = palo-alto-networks-leef-vpn-login
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """LEEF:""","""|Palo Alto Networks|PAN-OS Syslog Integration|""","""Subtype=globalprotect""",  """-succ|""", """user login succeeded""" ]
  Fields = [
    """\|ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """User name:\s{0,100}({user}[^,\s@]{1,2000})""",
    """User name:\s{0,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """DeviceName =({host}[\w\-.]{1,2000})""",
    """from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """Severity=({severity}[^\s|]{1,2000})""",
    """cat=({category}[^\s|]{1,2000})""", 
    """Client OS ( version)?.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""   
  ]
}
}
```