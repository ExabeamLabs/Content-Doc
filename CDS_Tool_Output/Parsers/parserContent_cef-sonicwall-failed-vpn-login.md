#### Parser Content
```Java
{
Name = cef-sonicwall-failed-vpn-login
  Vendor = Sonicwall
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """|User login failed""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s+(\w+=|$)""",
    """\|User login failed - ({failure_reason}.+?)\|""",
  ]
}

{
  Name = cef-sonicwall-rdp-logon
  Vendor = Sonicwall
  Lms = ArcSight
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Sonicwall|VPN|""", """cs2Label=Protocol""", """cs2=RDP"""]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\sduser=(|({user}.+?))\s+(\w+=|$)""",
    """\scs2=(|({logon_type_text}.+?))\s+(\w+=|$)""",
  ]
}
```