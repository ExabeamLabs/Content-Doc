#### Parser Content
```Java
{
Name = syslog-dhcpd-2
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"program":"dhcpd"""", """"logT":"DHCP-LINUX"""", """"message":"DHCPREQUEST""" ]
  Fields = [
    """"@timestamp":"({time}[^"]+)""",
    """"host":"({host}[^"]+)""",
    """"message":"DHCPREQUEST for ({dest_ip}[A-Fa-f:\d.]+)( \(({dest_host}[^\s\)]+)\))? from ({dest_mac}\S+)( \(({=dest_host}[^\s\)]+)\))? via ({dest_interface}[^\\"]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```