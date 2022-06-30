#### Parser Content
```Java
{
Name = q-asa-722037-vpn-end
  Vendor = Cisco
  Product = Adaptive Security Appliance
  Lms = QRadar
  DataType = "vpn-end"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "SVC closing connection:", "-722037" ]
  Fields = [ 
   """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
   """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
   """[\s\t]{1,2000}\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000}).+?%ASA""",
   """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
   """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
   """%(FTD|ASA)(-\w+)?-({priority}\d{1,100})-({event_code}\d{1,100})""",
   """Group\s{0,100}<({group}.*?)>""",
   """IP\s{0,100}<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>\s{0,100}({event_name}.*?):\s""",
   """User\s{0,100}<(({domain}[^\\\/]{1,2000})[\\\/])?(({user_email}[^@>]{1,2000}@[^>\.]{1,2000}\.[^>]{1,2000})|({user}[^>]{1,2000}))\s{0,100}>"""
]


}
```