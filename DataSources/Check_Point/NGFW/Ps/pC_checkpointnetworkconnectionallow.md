#### Parser Content
```Java
{
Name = checkpoint-network-connection-allow
  Vendor = Check Point
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ CheckPoint """, """action:Allow""", """product=VPN-1 & FireWall-1""", """origin:""" ]
  Fields = [
    """\Wtime:({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wsrc:({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst:({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """({outcome}Allow)""",
    """\Ws_port:({src_port}\d{1,100})""",
    """\Wifdir:({direction}[^"]{1,2000})""",
    """\Wservice:({dest_port}\d{1,100})""",
    """\Wproto:({protocol}[^"]{1,2000})""",
    """\Wpolicy_name=({rule}[^"]{1,2000}?)\\\]"""
  ]


}
```