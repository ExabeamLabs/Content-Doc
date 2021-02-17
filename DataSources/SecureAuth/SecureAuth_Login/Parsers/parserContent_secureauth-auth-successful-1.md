#### Parser Content
```Java
{
Name = secureauth-auth-successful-1
  Vendor = SecureAuth
  Product = SecureAuth Login
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """EventID="20000"""", """Authentication Success""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Timestamp="({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """\WUserHostAddress="({src_ip}[a-fA-F:\d.]+)""",
    """\WRealm="({realm}[^"]+)""",
    """\WAppliance="({host}[\w\-.]+)""",
    """\WAppliance="({dest_host}[\w\-.]+)""",
    """\WUserID="({user}[^"]+)""",
    """\WPriority="({priority}\d+)""",
    """\WEventID="({event_code}\d+)""",
    """({event_name}Authentication Success)""",
    """UserAgent="(?:-|Mozilla\/.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))"""
  ]
}
```