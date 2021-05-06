#### Parser Content
```Java
{
Name = asa-svc-vpn-716002-end
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Sumo
    DataType = "vpn-end"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "WebVPN session terminated" , "-716002" ]
    Fields = [
      """exabeam_raw=.+?({time}\w+ \d+ \d\d\d\d \d+:\d+:\d\d)""",
      """exabeam_host=(.+?@\s*)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
      """[\s\t]+\d\d:\d\d:\d\d\s+({host}[\w.\-]+).+?%ASA""",
      """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
      """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
      """User\s+<({user}[^>]+)>""",
      """IP\s+<({src_ip}[^>]+)>""",
      """%ASA-({priority}\d+)-({event_code}\d+)""",
      """Group\s*<({group}.*?)>""",
     ]
     DupFields = [ "group->realm", "dest_host->host"]
  }
```