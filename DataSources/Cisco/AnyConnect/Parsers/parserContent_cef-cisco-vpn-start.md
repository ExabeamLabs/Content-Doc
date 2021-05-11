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
    """\srt=({time}\d{0,100})""",
    """\ssourceTranslatedAddress=({src_ip}[^\s]+)""",
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_translated_ip}[^\s]+)""",
    """\sdvc=({dest_ip}[^\s]+)""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({dest_host}[^\s]+)"""
    """\sdvchost=({host}[^\s]+)""",
    """\scs1=({realm}[^\s]+).*?cs1Label=Group""", 
  ]
  DupFields = ["user->account"]
}
```