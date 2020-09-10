#### Parser Content
```Java
{
Name = asa-nap-cef-vpn-end
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = ArcSight
    DataType = "vpn-end"
    TimeFormat = "epoch"
    Conditions = [ "CEF:","""|CISCO|ASA""", """|Session is being torn down|""" ]
    Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
      """\srt=({time}\d+)""",
      """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sduser=({user}.+?)\s+\w+=""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)"""
    ]
  }
```