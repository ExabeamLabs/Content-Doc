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
    """\ssourceTranslatedAddress=({src_ip}[^\s]{1,2000})""",
    """\sduser=(?:({domain}[^\s]{1,2000}?)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_translated_ip}[^\s]{1,2000})""",
    """\sdvc=({dest_ip}[^\s]{1,2000})""",
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({dest_host}[^\s]{1,2000})"""
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\scs1=({realm}[^\s]{1,2000}).*?cs1Label=Group""", 
  ]
  DupFields = ["user->account"]
}
```