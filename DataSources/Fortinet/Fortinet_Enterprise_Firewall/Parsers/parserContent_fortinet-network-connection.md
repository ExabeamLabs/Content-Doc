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
    """\Wdevname="?({host}[^"]+?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wdstintf="({dest_interface}[^"]+)""",
    """\Wsrcintf="({src_interface}[^"]+)""",
    """\Wuser="({user}[^"]+)""",
    """\Wservice="?({protocol}\w+)""",
    """\Wsentbyte=({bytes_out}\d{1,100})""",
    """\Wrcvdbyte=({bytes_in}\d{1,100})""",
    """\Waction="?({outcome}[^"]+?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsentpkt=({packets_sent}\d{1,100})""",
    """policyid=({policy_id}\d{1,100})"""
    """\Wproto=({protocol}\d{1,100})""",
    """\Wsrcintfrole="(undefined|({src_interface_role}[^"]+))"""",
    """\Wdstintfrole="(undefined|({dest_interface_role}[^"]+))""""
  ]
}
```