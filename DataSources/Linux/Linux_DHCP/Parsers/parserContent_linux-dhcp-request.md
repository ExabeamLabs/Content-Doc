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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}dhcpd(\[\d{1,100}\])?:\s{1,100}DHCPREQUEST for ({dest_ip}[a-fA-F\d\.:]{1,2000})\s.*?from ({dest_mac}[a-fA-F\d\.:]{1,2000})(\s\(({dest_host}\S+)\))?( via (({src_ip}[\d.:a-fA-F]{1,2000}[\da-fA-F]):?|({dest_interface}[\w-]{1,2000})))\s{0,100}""",
  ]
  DupFields = [ "host->auth_server" ]
}
```