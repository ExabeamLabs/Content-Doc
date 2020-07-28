#### Parser Content
```Java
{
Name = asa-svc-vpn-start-iPhone
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "-iPhone> IP", "-722051" ]
    Fields = [
      """({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """User[\s\t]+<({user}.+?)-({src_host}[\w]+-iPhone)>[\s\t]+IP[\s\t]+<({src_ip}[^>]+)>[\s\t]+(?:IPv4[\s\t])?Address[\s\t]+<({src_translated_ip}[^>]+)>"""
    ]
  }
```