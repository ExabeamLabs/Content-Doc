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
      """QIP\[\-\]:([^,]{0,2000}
```