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
    Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sduser=({user}.+?)\s{1,100}\w+=""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})""",  
      """\sad.Group=({realm}\w+)""",
    ]
    DupFields = ["user->account"]
  }
```