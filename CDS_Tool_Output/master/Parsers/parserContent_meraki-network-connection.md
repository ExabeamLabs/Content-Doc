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
    """({time}\d+)\.\d+\s+({host}[\w.\-]+)\s+flows\s""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+) ({time}\d+)\.\d+ \S+\s+flows\s""",    
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sprotocol=({protocol}\w+)""",
    """\ssport=({src_port}\d+)""",
    """\sdport=({dest_port}\d+)""",
    """\sflows\s+({outcome}\w+)\s""",
    """\spattern:\s*({outcome}\w+)""",
    """\smac=({src_mac}[a-fA-F\d.:]+)""",
  ]
}
```