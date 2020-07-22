#### Parser Content
```Java
{
Name = q-asa-722037-vpn-end
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = QRadar
  DataType = "vpn-end"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "SVC closing connection:", "-722037" ]
  Fields = [ 
   """({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
   """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
   """[\s\t]+\d\d:\d\d:\d\d\s+({host}[\w.\-]+).+?%ASA""",
   """%ASA-({priority}\d+)-({event_code}\d+)""",
   """Group\s*<({group}.*?)>""",
   """IP\s*<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>\s*({event_name}.*?):\s""",
   """User\s*<({user}[^@>]+)(?:@({domain}[^>]+))?>"""
]
}
```