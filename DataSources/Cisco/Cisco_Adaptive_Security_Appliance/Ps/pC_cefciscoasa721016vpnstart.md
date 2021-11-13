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
    """\srt=({time}\d{1,100})""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\sdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
    """\sdhost=({dest_host}.+?)\s{1,100}\w+=""",  
  ]
  DupFields = ["user->account"]


}
```