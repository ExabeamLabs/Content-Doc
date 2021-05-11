#### Parser Content
```Java
{
Name = cef-f5-vpn-end
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """|F5|Big IP|""", """Acc-Stat:STOP""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=\w+\/({host}[\w\-.]+)""",
    """\WUser-Name:\s{0,100}(|({user}[^\s,]+)),""",
    """\WSession-ID:\s{0,100}(|({session_id}[^\s,]+)),""",
    """\WFramed-IP-Address:\s{0,100}(|({src_translated_ip}[A-Fa-f:\d.]+)),""",
  ]
}
```