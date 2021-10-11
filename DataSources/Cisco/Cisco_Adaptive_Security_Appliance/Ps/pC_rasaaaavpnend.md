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
  }, 

  {
    Name = asa-svc-vpn-start-iPhone
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "-iPhone> IP", "-722051" ]
    Fields = [
      """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """User[\s\t]{1,2000}<({user}.+?)-({src_host}[\w]{1,2000}-iPhone)>[\s\t]{1,2000}IP[\s\t]{1,2000}<({src_ip}[^>]{1,2000})>[\s\t]{1,2000}(?:IPv4[\s\t])?Address[\s\t]{1,2000}<({src_translated_ip}[^>]{1,2000})>"""
    ]
  }
```