#### Parser Content
```Java
{
Name = syslog-qip-dhcp
    Vendor = Nokia VitalQIP
  Product = Nokia VitalQIP
    Lms = Syslog
    DataType = "dhcp"
    TimeFormat = "dd/MM/yyyy HH:mm:ss"
    Conditions = [ "QIP[-]: " ]
    Fields = [
      """QIP\[\-\]:([^,]*,){6}\s*({dest_ip}[a-fA-F\d.:]+)""",
      """QIP\[\-\]:([^,]*,){7}\s*({dest_host}[^,]*?)\s*,""",
      """QIP\[\-\]:([^,]*,){8}\s*({domain}([^,\s]+\s*?)+?)\s*,""",
      """QIP\[\-\]:([^,]*,){10}\s*({user}[^,]*?)\s*,""",
      """QIP\[\-\]:([^,]*,){11}\s*({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    ]
  }
```