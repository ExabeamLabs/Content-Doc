#### Parser Content
```Java
{
Name = cef-aruba-nac-failed-logon
  Vendor = HP
  Product = Aruba Wireless controller
  Lms = ArcSight
  DataType = "nac-failed-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Aruba Networks|ClearPass|""", """|Failed Authentications|""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}.+?)\s{1,100}(w+=|$)""",
    """\Wdvchost=({host}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\Wreason=({failure_reason}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wcs1=({auth_server}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\Wduser=(?:({user_type}host)/)?(({domain}[^\\]{1,2000})\\+)?({user}[^\s\\\/]{1,2000})\s{1,100}([\w\.]{1,2000}=|$)""",
    """\Wdpriv=({access_type}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\Wdmac=({dest_mac}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
  ]
}
```