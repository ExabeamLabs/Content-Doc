#### Parser Content
```Java
{
Name = cef-sonicwall-failed-vpn-login
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """|User login failed""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s{1,100}(\w+=|$)""",
    """\|User login failed - ({failure_reason}.+?)\|""",
  ]
}
```