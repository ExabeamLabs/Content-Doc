#### Parser Content
```Java
{
Name = cef-aruba-nac-logon-1
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Aruba Networks|ClearPass|""", """|13003|""", ]
  Fields = [
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wduser=(({domain}[^\\]{1,2000})\\+)?({user}[^\s\\\/:]{1,2000})(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdmac=({dest_mac}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationServiceName=({network}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```