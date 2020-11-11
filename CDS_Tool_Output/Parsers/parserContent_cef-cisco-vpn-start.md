#### Parser Content
```Java
{
Name = cef-cisco-vpn-start
  Vendor = Cisco
  Product = AnyConnect
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "CEF:","""|CISCO|Cisco VPN|""", """|Received remote Proxy Host data in ID Payload|""","""sourceTranslatedAddress="""]
  Fields = [
    """\srt=({time}\d*)""",
    """\ssourceTranslatedAddress=({src_ip}[^\s]+)""",
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s+(\w+=|$)""",
    """\ssrc=({src_translated_ip}[^\s]+)""",
    """\sdvc=({dest_ip}[^\s]+)""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({dest_host}[^\s]+)"""
    """\sdvchost=({host}[^\s]+)"""
  ]
}
```