#### Parser Content
```Java
{
Name = asa-nap-cef-7.1.7-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = ArcSight
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "CEF:","""|CISCO|ASA|""", """|Assigned private IP address|""","""sourceTranslatedAddress"""]
    Fields = [ 
      """\srt=({time}\d*)""",
      """exabeam_EventTime=({eventtime}\d+)""",
      """\ssourceTranslatedAddress=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssuser=({user}.+?)\s+(\w+=|$)""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}.+?)\s+(\w+=|$)"""
    ]
  }
```