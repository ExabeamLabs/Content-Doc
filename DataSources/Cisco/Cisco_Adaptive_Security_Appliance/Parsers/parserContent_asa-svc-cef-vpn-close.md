#### Parser Content
```Java
{
Name = asa-svc-cef-vpn-close
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Direct
    DataType = "vpn-end"
    TimeFormat = "epoch"
    Conditions = [ """|CISCO|""", """|722037|SVC Closing Connection|""" ]
    Fields = [
      """exabeam_EventTime=({eventtime}\d+)""",
      """\srt=({time}\d+)""",
      """({event_code}722037)"""
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sduser=({user}[^\s@]+)\s+(\w+=|$)""",
      """\sduser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    ]
  }
```