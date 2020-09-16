#### Parser Content
```Java
{
Name = cef-f5-vpn-end
  Vendor = F5 Networks
  Product = Big-IP
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """|F5|Big IP|""", """Acc-Stat:STOP""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvchost=\w+\/({host}[\w\-.]+)""",
    """\WUser-Name:\s*(|({user}[^\s,]+)),""",
    """\WSession-ID:\s*(|({session_id}[^\s,]+)),""",
    """\WFramed-IP-Address:\s*(|({src_translated_ip}[A-Fa-f:\d.]+)),""",
  ]
}
```