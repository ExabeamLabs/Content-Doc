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
    """\srt=({time}\d{1,100})""",
    """\ssourceTranslatedAddress=({src_ip}[^\s]+)""",
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\sdvc=({dest_ip}[^\s]+)""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({dest_host}[^\s]+)"""
    """\sdvchost=({host}[^\s]+)"""
  ]
}
```