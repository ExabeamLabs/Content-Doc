#### Parser Content
```Java
{
Name = cef-sonicwall-vpn-start
  Vendor = Sonicwall
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """|User login successful|"""]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s+(\w+=|$)""",
    """\scs5Label=Portal\s.*cs5=({realm}.+?)\s+(\w+=|$)""",
    """\scs5=({realm}.+?)\s+(|\w+=.*)cs5Label=Portal\s""",
  ]
}
```