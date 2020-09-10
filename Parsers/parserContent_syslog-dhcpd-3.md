#### Parser Content
```Java
{
Name = syslog-dhcpd-3
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"program":"dhcpd"""", """"logT":"DHCP-LINUX"""", """"message":"Added new forward map""" ]
  Fields = [
    """"@timestamp":"({time}[^"]+)""",
    """"host":"({host}[^"]+)""",
    """"message":"Added new forward map from ({dest_host}[^\s]+) to ({dest_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```