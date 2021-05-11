#### Parser Content
```Java
{
Name = cef-sonicwall-vpn-start
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """|User login successful|"""]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s{1,100}(\w+=|$)""",
    """\scs5Label=Portal\s.*cs5=({realm}.+?)\s{1,100}(\w+=|$)""",
    """\scs5=({realm}.+?)\s{1,100}(|\w+=.*)cs5Label=Portal\s""",
  ]
  DupFields = ["user->account"]
}
```