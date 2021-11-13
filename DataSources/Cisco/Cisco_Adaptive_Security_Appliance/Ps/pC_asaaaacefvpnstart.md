#### Parser Content
```Java
{
Name = asa-aaa-cef-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = ArcSight
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "CEF:","""|CISCO|FWSM|""", """|Authentication succeeded|""" ]
    Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\ssrc=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
    ]
    DupFields = ["user->account"]
  

}
```