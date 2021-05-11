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
    """({host}[\w.\-]+)\s{1,100}CEF:""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wsuser=(n/a|(({domain}[^=\\\/]+)[\\\/]+)?({user}[^=\\\/]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs1=({reason}[^;\.]+)""",
    """Reason:\s{0,100}({reason}[^;\.]+)""",
    """<address>({src_ip}[a-fA-F\d.:]+)</address>""",
    """CLIENT:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```