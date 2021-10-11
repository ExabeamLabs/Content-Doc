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
      """QIP\[\-\]:([^,]{0,2000},){6}\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """QIP\[\-\]:([^,]{0,2000},){7}\s{0,100}({dest_host}[^,]{0,2000}?)\s{0,100},""",
      """QIP\[\-\]:([^,]{0,2000},){8}\s{0,100}({domain}([^,\s]{1,256}\s{0,100}?){1,256}?)\s{0,100},""",
      """QIP\[\-\]:([^,]{0,2000},){10}\s{0,100}({user}[^,]{0,2000}?)\s{0,100},""",
      """QIP\[\-\]:([^,]{0,2000},){11}\s{0,100}({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    ]
  }
```