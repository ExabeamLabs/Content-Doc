#### Parser Content
```Java
{
Name = linux-dhcp-request
  Vendor = Linux
  Product = Linux DHCP
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ DHCPREQUEST for """ , """ from """, """ via """ ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+dhcpd(\[\d+\])?:\s+DHCPREQUEST for ({dest_ip}[a-fA-F\d\.:]+)\s.*?from ({dest_mac}[a-fA-F\d\.:]+)(\s\(({dest_host}\S+)\))?( via (({src_ip}[\d.:a-fA-F]+[\da-fA-F]):?|({dest_interface}[\w-]+)))\s*""",
  ]
  DupFields = [ "host->auth_server" ]
}
```