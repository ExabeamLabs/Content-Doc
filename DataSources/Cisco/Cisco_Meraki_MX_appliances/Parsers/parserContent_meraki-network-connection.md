#### Parser Content
```Java
{
Name = meraki-network-connection
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ flows """, """ src=""", """ dst=""" ]
  Fields = [
    """({time}\d{1,100})\.\d{1,100}\s{1,100}({host}[\w.\-]+)\s{1,100}flows\s""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+) ({time}\d{1,100})\.\d{1,100} \S+\s{1,100}flows\s""",    
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sprotocol=({protocol}\w+)""",
    """\ssport=({src_port}\d{1,100})""",
    """\sdport=({dest_port}\d{1,100})""",
    """\sflows\s{1,100}({outcome}\w+)\s""",
    """\spattern:\s{0,100}({outcome}\w+)""",
    """\smac=({src_mac}[a-fA-F\d.:]+)""",
  ]
}
```