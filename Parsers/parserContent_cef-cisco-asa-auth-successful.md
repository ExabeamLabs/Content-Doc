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
    """\srt=({time}\d*)""",
    """\|({event_code}611101)""",
    """\sduser=(?:({domain}[^\s]+?)\\+)?({user}.+?)\s+([\w.]+=|$)""",
    """\sad\.Username=<?(?:({domain}[^\s]+?)\\+)?({user}.+?)>?\s+([\w.]+=|$)""",
    """\sdhost=({dest_host}.+?)\s+([\w.]+=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sdvc=({host}.+?)\s+([\w.]+=|$)""",
    """\sdvchost=({host}.+?)\s+([\w.]+=|$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```