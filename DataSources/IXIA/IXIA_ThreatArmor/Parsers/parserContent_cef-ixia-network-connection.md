#### Parser Content
```Java
{
Name = cef-ixia-network-connection
  Vendor = IXIA
  Product = IXIA ThreatArmor
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions= [ """CEF:""", """|IXIA|""", """src=""", """dst=""" ]
  Fields=[
    """\Wrt=({time}\d+)""",
    """\Wdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wproto=(|({protocol}.+?))(\s+\w+=|\s*$)""",
    """\Wreason=(|({failure_reason}.+?))(\s+\w+=|\s*$)""",
    """\Wact=(|({outcome}.+?))(\s+\w+=|\s*$)""",
  ]
}
```