#### Parser Content
```Java
{
Name = cef-microsoft-database-failed-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = ArcSight
  DataType = "database-failed-login"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ """CEF:""", """|LOGbinder|SQL|""", """|24003|Login failed|""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}CEF:""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wsuser=(n/a|(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({user}[^=\\\/]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs1=({reason}[^;\.]{1,2000})""",
    """Reason:\s{0,100}({reason}[^;\.]{1,2000})""",
    """<address>({src_ip}[a-fA-F\d.:]{1,2000})</address>""",
    """CLIENT:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]


}
```