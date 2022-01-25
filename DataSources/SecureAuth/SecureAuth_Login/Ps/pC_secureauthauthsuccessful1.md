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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Timestamp="({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """\WUserHostAddress="({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\WRealm="({realm}[^"]{1,2000})""",
    """\WAppliance="({host}[\w\-.]{1,2000})""",
    """\WAppliance="({dest_host}[\w\-.]{1,2000})""",
    """\WUserID="({user}[^"]{1,2000})""",
    """\WPriority="({priority}\d{1,100})""",
    """\WEventID="({event_code}\d{1,100})""",
    """({event_name}Authentication Success)""",
    """UserAgent="({user_agent}[^"]+)""",
  ]


}
```