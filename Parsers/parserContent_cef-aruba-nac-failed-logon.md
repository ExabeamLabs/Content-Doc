#### Parser Content
```Java
{
Name = cef-aruba-nac-failed-logon
  Vendor = HP Aruba
  Lms = ArcSight
  DataType = "nac-failed-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Aruba Networks|ClearPass|""", """|Failed Authentications|""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}.+?)\s+(w+=|$)""",
    """\Wdvchost=({host}.+?)\s+([\w\.]+=|$)""",
    """\Wreason=({failure_reason}.+?)\s+([\w\.]+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs1=({auth_server}.+?)\s+([\w\.]+=|$)""",
    """\Wduser=(?:({user_type}host)/)?(({domain}[^\\]+)\\+)?({user}[^\s\\\/]+)\s+([\w\.]+=|$)""",
    """\Wdpriv=({access_type}.+?)\s+([\w\.]+=|$)""",
    """\Wdmac=({dest_mac}.+?)\s+([\w\.]+=|$)""",
  ]
}
```