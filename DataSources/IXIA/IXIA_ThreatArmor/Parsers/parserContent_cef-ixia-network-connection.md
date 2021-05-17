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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wproto=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wreason=(|({failure_reason}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```