#### Parser Content
```Java
{
Name = linux-dhcp-request
  Vendor = Linux
  Product = Linux DHCP
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ DHCPREQUEST for """ , """ from """, """ via """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """({host}[a-fA-F\d\.:]+)\s+DHCPREQUEST for ({dest_ip}[a-fA-F\d\.:]+)\s.*?from ({dest_mac}[a-fA-F\d\.:]+)(\s\(({dest_host}\S+)\))?( via ({dest_interface}\S+?):?\s)?""",
  ]
  DupFields = [ "host->auth_server" ]
}
```