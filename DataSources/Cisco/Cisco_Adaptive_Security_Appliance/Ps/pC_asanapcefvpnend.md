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
    Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sduser=({user}.+?)\s{1,100}\w+=""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})"""
    ]
  

}
```