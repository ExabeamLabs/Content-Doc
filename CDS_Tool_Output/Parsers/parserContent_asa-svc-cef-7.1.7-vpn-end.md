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
      """exabeam_EventTime=({eventtime}\d+)""",
      """\srt=({time}\d+)""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sduser=({user_fullname}(\w+\s+)+\w+)\s+(\w+=|$)""",
      """\sduser=({user}[^\s@]+)\s+(\w+=|$)""",
      """\sduser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}.+?)\s+(\w+=|$)""",
      """\scs6=[^=]*?({session_hour}\d+)h:({session_min}\d+)m:({session_sec}\d+)s""",
      """\sin=({bytes_in}\d+)""",
      """\sout=({bytes_out}\d+)""",
    ]
  }
```