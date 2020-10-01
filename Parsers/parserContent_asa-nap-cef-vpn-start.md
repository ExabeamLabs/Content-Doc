#### Parser Content
```Java
{
Name = asa-nap-cef-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = ArcSight
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "CEF:","""|CISCO|ASA|""", """|Assigned private IP address|""" ]
    Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
      """\srt=({time}\d+)""",
      """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sduser=({user}.+?)\s+\w+=""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",  
      """\sad.Group=({realm}\w+)""",
    ]
    DupFields = ["user->account"]
  }
```