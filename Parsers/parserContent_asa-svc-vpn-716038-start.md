#### Parser Content
```Java
{
Name = asa-svc-vpn-716038-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Sumo
    DataType = "vpn-start"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "WebVPN", "Authentication: successful" , "-716038" ]
    Fields = [
      """exabeam_raw=.+?({time}\w+ \d+ \d\d\d\d \d+:\d+:\d\d)""",
      """exabeam_host=(.+?@\s*)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
      """User\s+<({user}[^>]+)>""",
      """IP\s+<({src_ip}[^>]+)>""",
      """%ASA-({priority}\d+)-({event_code}\d+)""",
      """Group\s*<({group}.*?)>""",
     ]
     DupFields = [ "group->realm", "dest_host->host"]
  }
```