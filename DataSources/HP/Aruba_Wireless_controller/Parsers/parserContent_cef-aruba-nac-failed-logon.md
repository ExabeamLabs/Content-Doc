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
    """\Wdvchost=({host}.+?)\s{1,100}([\w\.]+=|$)""",
    """\Wreason=({failure_reason}.+?)\s{1,100}([\w\.]+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs1=({auth_server}.+?)\s{1,100}([\w\.]+=|$)""",
    """\Wduser=(?:({user_type}host)/)?(({domain}[^\\]+)\\+)?({user}[^\s\\\/]+)\s{1,100}([\w\.]+=|$)""",
    """\Wdpriv=({access_type}.+?)\s{1,100}([\w\.]+=|$)""",
    """\Wdmac=({dest_mac}.+?)\s{1,100}([\w\.]+=|$)""",
  ]
}
```