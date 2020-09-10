#### Parser Content
```Java
{
Name = secureauth-auth-successful-1
  Vendor = SecureAuth
  Product = SecureAuth Login
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """EventID="20000"""", """Authentication Success""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
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