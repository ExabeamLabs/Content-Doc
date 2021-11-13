#### Parser Content
```Java
{
Name = cef-cisco-asa-auth-successful
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|ASA|""", """|611101|""" ]
  Fields = [
    """\srt=({time}\d{0,100})""",
    """\|({event_code}611101)""",
    """\sduser=(?:({domain}[^\s]{1,2000}?)\\+)?({user}.+?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sad\.Username=<?(?:({domain}[^\s]{1,2000}?)\\+)?({user}.+?)>?\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdhost=({dest_host}.+?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdvc=({host}.+?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdvchost=({host}.+?)\s{1,100}([\w.]{1,2000}=|$)"""
  ]
  DupFields = [ "host->dest_host" ]


}
```