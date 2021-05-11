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
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s{1,100}([\w.]+=|$)""",
    """\sad\.Username=<?(?:({domain}[^\s]+?)\\+)?({user}.+?)>?\s{1,100}([\w.]+=|$)""",
    """\sdhost=({dest_host}.+?)\s{1,100}([\w.]+=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sdvc=({host}.+?)\s{1,100}([\w.]+=|$)""",
    """\sdvchost=({host}.+?)\s{1,100}([\w.]+=|$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```