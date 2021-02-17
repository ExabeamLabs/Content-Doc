#### Parser Content
```Java
{
Name = cef-cisco-asa-113039-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|ASA|""", """|113039|""" ]
  Fields = [
    """\srt=({time}\d*)""",
    """\|({event_code}113039)""",
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s+([\w.]+=|$)""",
    """\sdhost=({dest_host}.+?)\s+([\w.]+=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sdvchost=({host}.+?)\s+([\w.]+=|$)""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```