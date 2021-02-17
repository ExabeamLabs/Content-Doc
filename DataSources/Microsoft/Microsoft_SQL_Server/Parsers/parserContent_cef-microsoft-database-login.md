#### Parser Content
```Java
{
Name = cef-microsoft-database-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = ArcSight
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ """CEF:""", """|LOGbinder|SQL|""", """|24001|Login succeeded""" ]
  Fields = [
    """({host}[\w.\-]+)\s+CEF:""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\W(d|s)user=(n/a|(({domain}[^=\\\/]+)[\\\/]+)?({user}[^=\\\/]+?))(\s+\w+=|\s*$)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """network protocol:\s*({protocol}[^;]+)""",
    """<address>({src_ip}[a-fA-F\d.:]+)</address>""",
  ]
}
```