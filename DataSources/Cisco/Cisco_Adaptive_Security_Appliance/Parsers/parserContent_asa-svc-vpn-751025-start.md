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
      """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """\-\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000}) : %ASA""",
      """Username:({user}.+?) IKEv2 """,
      """Local:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Remote:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """IPv4 Address=(?:0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """IPv6 address=(?:0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """Group:({realm}[^\s]{1,2000})""",
    ]
    DupFields = ["user->account"]
  }
```