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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """DAP: User ({user}[^,]{1,2000})""",
      """, Addr ({src_ip}[a-fA-F\d.:]{1,2000}): Session""",
      """endpoint.device.hostname="{0,20}({src_host}[^"\s]{1,2000})"""
    ]
    DupFields = ["user->account"]
  

}
```