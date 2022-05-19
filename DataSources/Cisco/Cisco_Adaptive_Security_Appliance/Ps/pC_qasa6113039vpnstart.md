#### Parser Content
```Java
{
Name = q-asa-6-113039-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = QRadar
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-113039", "%ASA-" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d)""",
    """User\s{1,100}<(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^@>]{1,2000})(?:@[^>]{1,2000})?>""",
    """User\s{1,100}<({user_email}[^@>]{1,2000}@[^@>]{1,2000})>""",
    """ IP <({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s{1,100}<({realm}.+?)>""",
  ]
  DupFields = [ "dest_host->host" , "user->account"]


}
```