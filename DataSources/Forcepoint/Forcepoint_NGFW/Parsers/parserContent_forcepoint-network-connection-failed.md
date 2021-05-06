#### Parser Content
```Java
{
Name = forcepoint-network-connection-failed
  Product = Forcepoint NGFW
  DataType = "network-connection-failed"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Discarded|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s*({protocol}.+?)(\s\w+=)""",
    ]
}
forcepoint-template = {
  Vendor = Forcepoint
  Product = Forcepoint
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields=[
    """CEF:\s+\d+\|([^\|]+\|){4}({activity}[^\|]+)""",
    """ahost=\s*({host}.+?)(\s\w+=)""",
    """\Wrt=({time}\d+)""",
    """src=\s*({src_ip}[A-Za-z\d.:]+)""".
    """dhost=\s*({dest_host}.+?)(\s\w+=)""",
    """dst=\s*({dest_ip}.+?)(\s\w+=)""",
    """amac=\s*({mac}.+?)(\s\w+=)""",
    """dvc=\s*({src_host}.+?)(\s\w+=)""",
    """app=\s*({protocol}.+?)(\s\w+=)""",
    """\Win=({bytes_in}\d+)""",
    """\Wout=({bytes_out}\d+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\sdeviceInboundInterface=({src_interface}.+?)\s*\w+=""",
    """\sdeviceOutboundInterface=({dest_interface}.+?)\s*\w+=""",
    """\sproto=({protocol}.+?)\s*\w+=""",
    ]

```