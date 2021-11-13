#### Parser Content
```Java
{
Name = r-asa-aaa-vpn-end
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = RsaSa
    DataType = "vpn-end"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "Authen Session End:", "rsa_sa_log" ]
    Fields = [ 
      	       """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d):""",
               """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
               """Authen Session End: user '({user}[^']{1,2000})'""" ]
  

}
```