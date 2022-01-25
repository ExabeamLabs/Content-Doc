#### Parser Content
```Java
{
Name = cef-microsoft-database-failed-login-1
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = ArcSight
  DataType = "database-failed-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|SQL Server|""", """:18456|Login failed""" ]
  Fields = [
    """\Wrt=({time}\d{10,13})""",
    """\Wsuser=(n/a|(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({user}[^=\\\/]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Reason:\s{0,100}({reason}[^;\.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """externalId=({event_code}18456)""",
    """\ssourceServiceName =({service_name}[^=]{1,2000}?)\s{0,100}\w+=""",
    """\Wdvchost=({dest_host}[\w\-.]{1,2000})""",
    """\sahost=({host}[^=]{1,2000}?)(\s{0,100}[\w\.]{1,2000}=)""",
    """\sshost=({src_host}[\w\.\-]{1,200}?)\s{0,100}[\w\-\.]{1,2000}="""
  ]


}
```