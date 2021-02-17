#### Parser Content
```Java
{
Name = fortinet-network-connection
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """type=""", """traffic""", """action=""", """service=""", """date=""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="?({host}[^"]+?)"?(\s+\w+=|\s*$)""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wsrcport=({src_port}\d+)""",
    """\Wdstport=({dest_port}\d+)""",
    """\Wdstintf="({dest_interface}[^"]+)""",
    """\Wsrcintf="({src_interface}[^"]+)""",
    """\Wuser="({user}[^"]+)""",
    """\Wservice="?({protocol}\w+)""",
    """\Wsentbyte=({bytes_out}\d+)""",
    """\Wrcvdbyte=({bytes_in}\d+)""",
    """\Waction="?({outcome}[^"]+?)"?(\s+\w+=|\s*$)""",
    """\Wsentpkt=({packets_sent}\d+)""",
  ]
}
```