#### Parser Content
```Java
{
Name = s-infoblox-dhcp-2
  Vendor = Infoblox
  Product = Infoblox
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " dhcpd[", ": DHCPOFFER " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+) dhcpd\[""",
    """: ({event_name}DHCPOFFER) on ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to ({dest_mac}[^\s]{1,2000})( \(({dest_host}[\w\-.]{1,2000})\))?\s{1,100}via ({dest_interface}[^\s]{1,2000})""",
  ]
  DupFields = [ "dest_host->user" ]


}
```