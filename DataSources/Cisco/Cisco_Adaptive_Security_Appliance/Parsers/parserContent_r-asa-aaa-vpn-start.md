#### Parser Content
```Java
{
Name = r-asa-aaa-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = RsaSa
    DataType = "vpn-start"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "Authentication succeeded for user" , "-109005", "rsa_sa_log" ]
    Fields = [
	       """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d):""",
               """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
               """Authentication succeeded for user '({user}[^']{1,2000})' from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?to ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""" ]
  }
```