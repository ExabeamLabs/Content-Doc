#### Parser Content
```Java
{
Name = cef-checkpoint-firewall
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = ArcSight
  TimeFormat = "epoch"
  IsHVF = true
  DataType = "network-connection"
  Conditions = [ """|Check Point|VPN-1 & FireWall-1|""", """categoryBehavior=/Access""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wproto=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=({action}.+?)\s{1,100}(\w+=|$)""",
    """\WdeviceDirection=({direction}\d{1,100})""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\WdestinationServiceName =({service}.+?)\s{1,100}(\w+=|$)""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wreason=(?:;|({failure_reason}.+?))\s{1,100}(\w+=|$)""",
    """\Wcs1=(?:\s\&|({rule}.+?))\s{1,100}(\w+=|$)"""
  ]


}
```