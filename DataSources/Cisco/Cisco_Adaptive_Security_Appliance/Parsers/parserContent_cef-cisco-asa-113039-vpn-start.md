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
    """\srt=({time}\d{0,100})""",
    """\|({event_code}113039)""",
    """\sduser=(?:({domain}[^\s]{1,2000}?)\\+)?({user}.+?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdhost=({dest_host}.+?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdvchost=({host}.+?)\s{1,100}([\w.]{1,2000}=|$)""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```