#### Parser Content
```Java
{
Name = fortinet-network-connection
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """type=""", """traffic""", """action=""", """service=""", """date=""" ]
  Fields = [
    """eventtime=({time}\d{1,10})""",
    """\Wdevname="?({host}[^"]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """eventtime=({time}\d{1,20})""",
    """\Wdevname="?({host}[^"]{1,2000}?)"?(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wdstintf="({dest_interface}[^"]{1,2000})""",
    """\Wsrcintf="({src_interface}[^"]{1,2000})""",
    """\Wuser="({user}[^"]{1,2000})""",
    """\Wsentbyte=({bytes_out}\d{1,100})""",
    """\Wrcvdbyte=({bytes_in}\d{1,100})""",
    """\Waction="?({outcome}[^"]{1,2000}?)"?(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wsentpkt=({packets_sent}\d{1,100})""",
    """policyid=({policy_id}\d{1,100})"""
    """\Wproto=({protocol}\d{1,100})""",
    """\Wservice="?({protocol}[^"]{1,2000})""",
    """\Wsrcintfrole="(undefined|({src_interface_role}[^"]{1,2000}))"""",
    """\Wdstintfrole="(undefined|({dest_interface_role}[^"]{1,2000}))""""
  ]


}
```