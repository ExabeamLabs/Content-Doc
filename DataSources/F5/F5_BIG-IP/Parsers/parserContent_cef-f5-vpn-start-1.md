#### Parser Content
```Java
{
Name = cef-f5-vpn-start-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|F5|Big IP|""", """Acc-Stat:START""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=\w+\/({host}[\w\-.]+)""",
    """\WUser-Name:\s{0,100}(|({user}[^\s,]+)),""",
    """\WSession-ID:\s{0,100}(|({session_id}[^\s,]+)),""",
    """\WTunnel-Client-Endpoint:\s{0,100}(|({src_ip}[A-Fa-f:\d.]+)),""",
    """\WFramed-IP-Address:\s{0,100}(|({src_translated_ip}[A-Fa-f:\d.]+)),""",
  ]
}
```