#### Parser Content
```Java
{
Name = asa-svc-cef-7.1.7-vpn-end
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = ArcSight
    DataType = "vpn-end"
    TimeFormat = "epoch"
    Conditions = [ """|CISCO|""", """|113019|Session disconnected|""" ]
    Fields = [ 
      """exabeam_EventTime=({eventtime}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sduser=({user_fullname}(\w+\s{1,100})+\w+)\s{1,100}(\w+=|$)""",
      """\sduser=({user}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
      """\sduser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
      """\scs6=[^=]{0,2000}?({session_hour}\d{1,100})h:({session_min}\d{1,100})m:({session_sec}\d{1,100})s""",
      """\sin=({bytes_in}\d{1,100})""",
      """\sout=({bytes_out}\d{1,100})""",
    ]
  }
```