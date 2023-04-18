#### Parser Content
```Java
{
Name = asa-svc-vpn-716002-end
    Vendor = Cisco
    Product = Adaptive Security Appliance
    Lms = Sumo
    DataType = "vpn-end"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "WebVPN session terminated" , "-716002" ]
    Fields = [
      """exabeam_raw=.+?({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d\d)""",
      """exabeam_host=(.+?@\s{0,100})?({host}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
      """\w{1,3}\s{1,2}\d{1,2}\s\d\d:\d\d:\d\d\s({host}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))\s%ASA-""",
      """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
      """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
      """User\s{1,100}<(({domain}[^\\\/]{1,2000})[\\\/])?(({user_email}[^@>]{1,2000}@[^>]{1,2000})|({user}[^>]{1,2000}))>""",
      """IP\s{1,100}<({src_ip}[^>]{1,2000})>""",
      """%(FTD|ASA)(-\w+)?-({priority}\d{1,100})-({event_code}\d{1,100})""",
      """Group\s{0,100}<({group}.*?)>""",
     ]
     DupFields = [ "group->realm"]
  

}
```