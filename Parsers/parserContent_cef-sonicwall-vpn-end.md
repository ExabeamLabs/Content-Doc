#### Parser Content
```Java
{
Name = cef-sonicwall-vpn-end
  Vendor = Sonicwall
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """logged out|"""]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s+(\w+=|$)""",
    """\scs4Label=Duration\s.*cs4=({session_duration}\d+)\s+(\w+=|$)""",
    """\scs4=({session_duration}\d+)\s+(|\w+=.*)cs4Label=Duration\s""",
  ]
}
```