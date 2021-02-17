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
    """"@timestamp":"({time}[^"]+)""",
    """"host":"({host}[^"]+)""",
    """"message":"DHCPACK on ({dest_ip}[A-Fa-f:\d.]+) to ({dest_mac}\S+)( \(({dest_host}[^\s\)]+)\))? via ({dest_interface}[^\\"]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```