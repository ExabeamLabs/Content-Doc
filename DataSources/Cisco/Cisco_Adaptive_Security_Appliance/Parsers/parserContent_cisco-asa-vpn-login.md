#### Parser Content
```Java
{
Name = cisco-asa-vpn-login
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Direct
    DataType = "vpn-start"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """DAP: User""", """endpoint.device.hostname""" ]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """DAP: User ({user}[^,]+)""",
      """, Addr ({src_ip}[a-fA-F\d.:]+): Session""",
      """endpoint.device.hostname="{0,20}({src_host}[^"\s]+)"""
    ]
    DupFields = ["user->account"]
  }
```