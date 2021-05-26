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
    """\ssourceTranslatedAddress=({src_ip}[^\s]{1,2000})""",
    """\sduser=(?:({domain}[^\s]{1,2000}?)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\sdvc=({dest_ip}[^\s]{1,2000})""",
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({dest_host}[^\s]{1,2000})"""
    """\sdvchost=({host}[^\s]{1,2000})"""
  ]
}
```