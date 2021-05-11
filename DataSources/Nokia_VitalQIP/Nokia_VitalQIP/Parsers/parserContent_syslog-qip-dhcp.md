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
      """QIP\[\-\]:([^,]*,){6}\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
      """QIP\[\-\]:([^,]*,){7}\s{0,100}({dest_host}[^,]*?)\s{0,100}
```