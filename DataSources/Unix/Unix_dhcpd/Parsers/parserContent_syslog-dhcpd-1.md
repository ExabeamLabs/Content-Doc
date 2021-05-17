#### Parser Content
```Java
{
Name = syslog-dhcpd-1
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"program":"dhcpd"""", """"logT":"DHCP-LINUX"""", """"message":"DHCPACK on""" ]
  Fields = [
    """"@timestamp":"({time}[^"]{1,2000})""",
    """"host":"({host}[^"]{1,2000})""",
    """"message":"DHCPACK on ({dest_ip}[A-Fa-f:\d.]{1,2000}) to ({dest_mac}\S+)( \(({dest_host}[^\s\)]{1,2000})\))? via ({dest_interface}[^\\"]{1,2000})""",
  ]
  DupFields = [ "dest_host->user" ]
}
```