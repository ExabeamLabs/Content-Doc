#### Parser Content
```Java
{
Name = s-infoblox-dhcp-1
  Vendor = Infoblox
  Product = Infoblox
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " dhcpd[", ": DHCPACK " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+) dhcpd\[""",
    """: DHCPACK to ({dest_ip}[A-Fa-f:\d.]{1,2000}) \(({dest_mac}[^\s\)]{1,2000})\)""",
    """: DHCPACK on ({dest_ip}[A-Fa-f:\d.]{1,2000}) to ({dest_mac}[^\s]{1,2000}) (\(({dest_host}[\w\-.]{1,2000})\))?""",
  ]
  DupFields = [ "dest_host->user" ]


}
```