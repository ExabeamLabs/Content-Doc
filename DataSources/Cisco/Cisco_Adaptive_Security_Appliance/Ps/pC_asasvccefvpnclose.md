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
      """exabeam_EventTime=({eventtime}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """({event_code}722037)"""
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sduser=({user}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
      """\sduser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    ]
  }
```