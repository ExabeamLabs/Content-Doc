#### Parser Content
```Java
{
Name = asa-aaa-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "Authentication succeeded for user" , "-109005" ]
    Fields = [ """exabeam_host=({host}[^\s]+)""",
      """({time}\w+ \d+ \d\d\d\d \d+:\d+:\d+)""",
      """Authentication succeeded for user '({user}[^']+)' from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?to ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""" ]
    DupFields = ["user->account"]
  }
```