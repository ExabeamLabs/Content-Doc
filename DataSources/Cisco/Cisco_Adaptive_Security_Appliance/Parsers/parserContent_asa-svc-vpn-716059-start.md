#### Parser Content
```Java
{
Name = asa-svc-vpn-716059-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Sumo
    DataType = "vpn-start"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "AnyConnect session resumed connection from IP" , "-716059" ]
    Fields = [
      """exabeam_raw=.+?({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d\d)""",
      """exabeam_host=(.+?@\s{0,100})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
      """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
      """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
      """User\s{1,100}<({user}[^>]{1,2000})>""",
      """IP\s{1,100}<({src_ip}[^>]{1,2000})>""",
      """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
      """Group\s{0,100}<({group}.*?)>""",
     ]
     DupFields = [ "group->realm", "dest_host->host"]
  }
```