#### Parser Content
```Java
{
Name = cef-aruba-nac-logon-1
  Vendor = HP Aruba
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Aruba Networks|ClearPass|""", """|13003|""", ]
  Fields = [
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wduser=(({domain}[^\\]+)\\+)?({user}[^\s\\\/:]+)(\s+\w+=|\s*$)""",
    """\Wdmac=({dest_mac}.+?)(\s+\w+=|\s*$)""",
    """\Wdst=({dest_ip}.+?)(\s+\w+=|\s*$)""",
    """\WdestinationServiceName=({network}.+?)(\s+\w+=|\s*$)""",
  ]
}
```