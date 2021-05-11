#### Parser Content
```Java
{
Name = cef-sonicwall-vpn-end
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """logged out|"""]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s{1,100}(\w+=|$)""",
    """\scs4Label=Duration\s.*cs4=({session_duration}\d{1,100})\s{1,100}(\w+=|$)""",
    """\scs4=({session_duration}\d{1,100})\s{1,100}(|\w+=.*)cs4Label=Duration\s""",
  ]
}
```