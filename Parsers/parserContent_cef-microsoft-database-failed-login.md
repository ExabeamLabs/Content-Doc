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
    """({host}[\w.\-]+)\s+CEF:""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wsuser=(n/a|(({domain}[^=\\\/]+)[\\\/]+)?({user}[^=\\\/]+?))(\s+\w+=|\s*$)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wcs1=({reason}[^;\.]+)""",
    """Reason:\s*({reason}[^;\.]+)""",
    """<address>({src_ip}[a-fA-F\d.:]+)</address>""",
    """CLIENT:\s*({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```