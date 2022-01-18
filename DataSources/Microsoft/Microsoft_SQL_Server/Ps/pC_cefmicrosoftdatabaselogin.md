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
    """({host}[\w.\-]{1,2000})\s{1,100}CEF:""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\W(d|s)user=(n/a|(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({user}[^=\\\/]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """network protocol:\s{0,100}({protocol}[^;]{1,2000})""",
    """<address>({src_ip}[a-fA-F\d.:]{1,2000})</address>""",
  ]


}
```