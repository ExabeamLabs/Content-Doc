#### Parser Content
```Java
{
Name = cef-windows-dns-response
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|DNS Server|""", """app=DNS Response""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wapp=({event_code}DNS Response)""",
    """\Wrequest=({query}.+?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wcs1=({query_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs5=({query_flags}.+?)\s{1,100}(\w+=|$)""",
    """\Wproto=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\WdeviceSeverity=({dns_response_code}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```