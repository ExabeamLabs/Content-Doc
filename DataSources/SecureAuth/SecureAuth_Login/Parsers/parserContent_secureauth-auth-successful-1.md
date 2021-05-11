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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Timestamp="({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """\WUserHostAddress="({src_ip}[a-fA-F:\d.]+)""",
    """\WRealm="({realm}[^"]+)""",
    """\WAppliance="({host}[\w\-.]+)""",
    """\WAppliance="({dest_host}[\w\-.]+)""",
    """\WUserID="({user}[^"]+)""",
    """\WPriority="({priority}\d{1,100})""",
    """\WEventID="({event_code}\d{1,100})""",
    """({event_name}Authentication Success)""",
    """UserAgent="(?:-|Mozilla\/.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))"""
  ]
}
```