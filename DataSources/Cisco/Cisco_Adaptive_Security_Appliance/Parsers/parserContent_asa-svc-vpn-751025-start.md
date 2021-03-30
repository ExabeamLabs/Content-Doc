#### Parser Content
```Java
{
Name = asa-svc-vpn-751025-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ "assigned to session", "-751025" ]
    Fields = [
      """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """\-\d\d:\d\d\s+({host}[\w.\-]+) : %ASA""",
      """Username:({user}.+?) IKEv2 """,
      """Local:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Remote:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """IPv4 Address=(?:0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """IPv6 address=(?:0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """Group:({realm}[^\s]+)""",
    ]
    DupFields = ["user->account"]
  }
```