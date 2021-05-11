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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}\S+) dhcpd\[""",
    """: DHCPACK to ({dest_ip}[A-Fa-f:\d.]+) \(({dest_mac}[^\s\)]+)\)""",
    """: DHCPACK on ({dest_ip}[A-Fa-f:\d.]+) to ({dest_mac}[^\s]+) (\(({dest_host}[\w\-.]+)\))?""",
  ]
  DupFields = [ "dest_host->user" ]
}
```