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
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wapp=({event_code}DNS Response)""",
    """\Wrequest=({query}.+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs1=({query_type}.+?)\s+(\w+=|$)""",
    """\Wcs5=({query_flags}.+?)\s+(\w+=|$)""",
    """\Wproto=({protocol}.+?)\s+(\w+=|$)""",
    """\WdeviceSeverity=({dns_response_code}.+?)\s+(\w+=|$)""",
  ]
}
```