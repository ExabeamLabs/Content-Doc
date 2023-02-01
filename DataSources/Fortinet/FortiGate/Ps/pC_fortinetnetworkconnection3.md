#### Parser Content
```Java
{
Name = fortinet-network-connection-3
  Vendor = Fortinet
  Product = FortiGate
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ """|Fortinet|Fortigate|""", """FTNTFGTeventtime=""", """FTNTFGTdstintfrole=""", """|traffic:forward """, """FTNTFGTsubtype=forward""" ]
  Fields = [
    """FTNTFGTeventtime=({time}\d{1,19})""",
    """\s\d\d:\d\d:\d\d\s({host}[\w\-\.]{1,2000})""",
    """\sshost=(({src_ip}[a-fA-F\d\.]{1,2000})|({src_host}[^\s]{1,2000}?))\s\w+=""",
    """\ssrc=({src_ip}[a-fA-F\d\.]{1,2000})""",
    """\sspt=({src_port}\d{1,5})""",
    """\sdhost=(({dest_ip}[a-fA-F\d\.]{1,2000})|({dest_host}[^\s]{1,2000}?))\s\w+=""",
    """\sdst=({dest_ip}[a-fA-F\d\.]{1,2000})""",
    """\sdpt=({dest_port}\d{1,5})""",
    """\sact=({action}[^=]{1,2000}?)\s\w+=""",
    """\sout=({bytes_out}\d{1,20})""",
    """\sin=({bytes_in}\d{1,20})""",    
    """\|Fortinet\|Fortigate\|([^|]{1,2000}\|){2}({event_name}[^|]{1,2000})\|""",
    """deviceInboundInterface=({src_interface}[^=]{1,2000}?)\s\w+=""",
    """deviceOutboundInterface=({dest_interface}[^=]{1,2000}?)\s\w+=""",
    """\sproto=({protocol}[^\s]{1,2000})"""
  ]


}
```