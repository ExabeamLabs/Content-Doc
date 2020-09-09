#### Parser Content
```Java
{
Name = s-nasuni-file-permission-change-2
    Conditions = [ """,CIFS,""", """,Set ACL,""" ]
  }
  ${NasuniParserTemplates.s-nasuni-file-operations}{
    Name = s-nasuni-file-write
    Conditions = [ """,CIFS,""", """,Write to File,""" ]
  }
  ${NasuniParserTemplates.s-nasuni-file-operations}{
    Name = s-nasuni-file-write-1
    Conditions = [ """,CIFS,""", """,Rename,""" ]
  }
  ${NasuniParserTemplates.s-nasuni-file-operations}{
    Name = s-nasuni-file-write-2
    Conditions = [ """,CIFS,""", """,Truncate File,""" ]
  }
  ${NasuniParserTemplates.s-nasuni-file-operations}{
    Name = s-nasuni-file-delete
    Conditions = [ """,CIFS,""", """,Delete File,""" ]
  }
  ${NasuniParserTemplates.s-nasuni-file-operations}{
    Name = s-nasuni-file-delete-1
    Conditions = [ """,CIFS,""", """,Delete Directory,""" ]
  }

{
  Name = openvpn-vpn-login
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """] AUTH SUCCESS """, """pvt_google_auth_secret_locked""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\+|\-)\d+).*?AUTH SUCCESS""",
    """'user':\s*.*?'({user}[^\s,]+)',""",
    """auth succeeded on.*?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```