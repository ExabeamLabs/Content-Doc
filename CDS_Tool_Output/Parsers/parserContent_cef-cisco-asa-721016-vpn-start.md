#### Parser Content
```Java
{
Name = cef-cisco-asa-721016-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|ASA|""", """|721016|""", """|WebVPN session created|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdst=({src_ip}[a-fA-F\d.:]+)""",
    """\sduser=({user}.+?)\s+(\w+=|$)""",
    """\sdvchost=({host}.+?)\s+(\w+=|$)""",
  ]
}
```