#### Parser Content
```Java
{
Name = cef-checkpoint-firewall
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = ArcSight
  TimeFormat = "epoch"
  IsHVF = true
  DataType = "network-connection"
  Conditions = [ """|Check Point|VPN-1 & FireWall-1|""", """categoryBehavior=/Access""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wproto=({protocol}.+?)\s+(\w+=|$)""",
    """\Wact=({action}.+?)\s+(\w+=|$)""",
    """\WdeviceDirection=({direction}\d+)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wspt=({src_port}\d+)""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdpt=({dest_port}\d+)""",
    """\WdestinationServiceName=({service}.+?)\s+(\w+=|$)""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wreason=(?:;|({failure_reason}.+?))\s+(\w+=|$)""",
    """\Wcs1=(?:\s\&|({rule}.+?))\s+(\w+=|$)"""
  ]
}
```