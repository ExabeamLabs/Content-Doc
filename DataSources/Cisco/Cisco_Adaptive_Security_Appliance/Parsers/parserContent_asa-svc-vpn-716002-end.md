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
      """exabeam_raw=.+?({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d\d)""",
      """exabeam_host=(.+?@\s{0,100})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
      """[\s\t]+\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]+).+?%ASA""",
      """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
      """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
      """User\s{1,100}<({user}[^>]+)>""",
      """IP\s{1,100}<({src_ip}[^>]+)>""",
      """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
      """Group\s{0,100}<({group}.*?)>""",
     ]
     DupFields = [ "group->realm", "dest_host->host"]
  }
```