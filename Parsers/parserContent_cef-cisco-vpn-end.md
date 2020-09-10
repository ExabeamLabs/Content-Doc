#### Parser Content
```Java
{
Name = cef-cisco-vpn-end
  Vendor = Cisco
  Product = AnyConnect
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "CEF:","""|CISCO|Cisco VPN|""", """|User disconnected|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\ssourceTranslatedAddress=({src_ip}[^\s]+)""",
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s+(\w+=|$)""",
    """\sdvc=({dest_ip}[^\s]+)""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({dest_host}[^\s]+)"""
    """\sdvchost=({host}[^\s]+)"""
  ]
}
```