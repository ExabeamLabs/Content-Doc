#### Parser Content
```Java
{
Name = cef-f5-vpn-start-1
  Vendor = F5 Networks
  Product = Big-IP
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|F5|Big IP|""", """Acc-Stat:START""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvchost=\w+\/({host}[\w\-.]+)""",
    """\WUser-Name:\s*(|({user}[^\s,]+)),""",
    """\WSession-ID:\s*(|({session_id}[^\s,]+)),""",
    """\WTunnel-Client-Endpoint:\s*(|({src_ip}[A-Fa-f:\d.]+)),""",
    """\WFramed-IP-Address:\s*(|({src_translated_ip}[A-Fa-f:\d.]+)),""",
  ]
}
```